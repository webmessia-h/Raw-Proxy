#include "../include/network.hpp"

#include <cerrno>
#include <cstdint>
#include <iostream>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <optional>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>

// Create connection request (SYN) packet
void create_syn_packet(struct sockaddr_in *src, struct sockaddr_in *dst,
                       unsigned char **packet, int *packet_size) {
  // TODO: check memory operations
  size_t datagram_size =
      sizeof(struct iphdr) + sizeof(struct tcphdr) + DATAGRAM_SIZE;
  std::vector<unsigned char> datagram(datagram_size);

  // Ip, tcp headers
  struct iphdr *iph = reinterpret_cast<struct iphdr *>(datagram.data());
  struct tcphdr *tcph =
      reinterpret_cast<struct tcphdr *>(datagram.data() + sizeof(struct iphdr));

  // Ip header configuration
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = htonl(datagram_size);
  iph->id = htonl(rand() & 65535);
  iph->frag_off = 0;
  iph->ttl = 64;
  iph->protocol = IPPROTO_TCP;
  iph->check = 0;
  iph->saddr = src->sin_addr.s_addr;
  iph->daddr = dst->sin_addr.s_addr;

  // TCP header configuration
  tcph->source = src->sin_port;
  tcph->dest = dst->sin_port;
  tcph->seq = htonl(rand() % 4294967295);
  tcph->ack_seq = htonl(0);
  tcph->doff = 10; // tcp header size
  tcph->fin = 0;
  tcph->syn = 1;
  tcph->rst = 0;
  tcph->psh = 0;
  tcph->ack = 0;
  tcph->urg = 0;
  tcph->check = 0;            // correct calculation follows later
  tcph->window = htons(5840); // window size
  tcph->urg_ptr = 0;

  // TCP options are only set in the SYN packet
  // ---- set mss ----
  datagram[40] = 0x02;
  datagram[41] = 0x04;
  int16_t mss = htons(48); // mss value
  memcpy(datagram.data() + 42, &mss, sizeof(int16_t));
  // ---- enable SACK ----
  datagram[44] = 0x04;
  datagram[45] = 0x02;

  // calculate checksum
  iph->check = Network::checksum(reinterpret_cast<unsigned short *>(iph),
                                 sizeof(struct iphdr));
  tcph->check = Network::checksum(reinterpret_cast<unsigned short *>(tcph),
                                  sizeof(struct tcphdr));
  *packet = datagram.data();
  *packet_size = iph->tot_len;
}

// Create ACK packet
void create_ack_packet(struct sockaddr_in *src, struct sockaddr_in *dst,
                       int32_t seq, int32_t ack_seq, unsigned char **packet,
                       int *packet_size) {
  // TODO: check memory operations
  size_t datagram_size =
      sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE;
  std::vector<unsigned char> datagram(datagram_size);

  // Ip, tcp headers
  struct iphdr *iph = reinterpret_cast<struct iphdr *>(datagram.data());
  struct tcphdr *tcph =
      reinterpret_cast<struct tcphdr *>(datagram.data() + sizeof(struct iphdr));

  // Ip header configuration
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = htonl(datagram_size);
  iph->id = htonl(rand() & 65535);
  iph->frag_off = 0;
  iph->ttl = 64;
  iph->protocol = IPPROTO_TCP;
  iph->check = 0;
  iph->saddr = src->sin_addr.s_addr;
  iph->daddr = dst->sin_addr.s_addr;

  // TCP header configuration
  tcph->source = src->sin_port;
  tcph->dest = dst->sin_port;
  tcph->seq = htonl(rand() % 4294967295);
  tcph->ack_seq = htonl(0);
  tcph->doff = 10; // tcp header size
  tcph->fin = 0;
  tcph->syn = 0;
  tcph->rst = 0;
  tcph->psh = 0;
  tcph->ack = 1;
  tcph->urg = 0;
  tcph->check = 0;            // correct calculation follows later
  tcph->window = htons(5840); // window size
  tcph->urg_ptr = 0;

  // TCP options are only set in the SYN packet
  // ---- set mss ----
  datagram[40] = 0x02;
  datagram[41] = 0x04;
  int16_t mss = htons(48); // mss value
  memcpy(datagram.data() + 42, &mss, sizeof(int16_t));
  // ---- enable SACK ----
  datagram[44] = 0x04;
  datagram[45] = 0x02;

  // calculate checksum
  iph->check = Network::checksum(reinterpret_cast<unsigned short *>(iph),
                                 sizeof(struct iphdr));
  tcph->check = Network::checksum(reinterpret_cast<unsigned short *>(tcph),
                                  sizeof(struct tcphdr));
  *packet = datagram.data();
  *packet_size = iph->tot_len;
}

// Create a data-filled packet
void Network::create_data_packet(struct sockaddr_in *src,
                                 struct sockaddr_in *dst, int32_t seq,
                                 int32_t ack_seq, const std::string &data,
                                 unsigned char **packet, int *packet_size) {
  // TODO: check memory operations
  size_t datagram_size =
      sizeof(struct iphdr) + sizeof(struct tcphdr) + data.size();
  std::vector<unsigned char> datagram(datagram_size);

  // Ip, tcp headers
  struct iphdr *iph = reinterpret_cast<struct iphdr *>(datagram.data());
  struct tcphdr *tcph =
      reinterpret_cast<struct tcphdr *>(datagram.data() + sizeof(struct iphdr));

  // Set payload
  std::copy(data.begin(), data.end(),
            datagram.begin() + sizeof(struct iphdr) + sizeof(struct tcphdr) +
                OPT_SIZE);

  // IP header configuration
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = htonl(datagram_size);
  iph->id = htons(rand() % 65535); // id of this packet
  iph->frag_off = 0;
  iph->ttl = 64;
  iph->protocol = IPPROTO_TCP;
  iph->check = 0;                    // calculation follows later
  iph->saddr = src->sin_addr.s_addr; // source adress
  iph->daddr = dst->sin_addr.s_addr;

  // TCP header configuration
  tcph->source = src->sin_port;
  tcph->dest = dst->sin_port;
  tcph->seq = htonl(seq);
  tcph->ack_seq = htonl(ack_seq);
  tcph->doff = 10; // tcp header size
  tcph->fin = 0;
  tcph->syn = 0;
  tcph->rst = 0;
  tcph->psh = 1;
  tcph->ack = 1;
  tcph->urg = 0;
  tcph->check = 0;            // calculation follows later
  tcph->window = htons(5840); // window size
  tcph->urg_ptr = 0;

  // calculate checksum
  iph->check = Network::checksum(reinterpret_cast<unsigned short *>(iph),
                                 sizeof(struct iphdr));
  tcph->check = Network::checksum(reinterpret_cast<unsigned short *>(tcph),
                                  sizeof(struct tcphdr));
  std::copy(data.begin(), data.end(),
            datagram.begin() + sizeof(struct iphdr) + sizeof(struct tcphdr));

  *packet = datagram.data();
  *packet_size = iph->tot_len;
}

int Network::create_socket(int domain, int type, int protocol) {
  int sockfd = socket(domain, type, protocol);
  if (sockfd < 0) {
    std::cerr << "Error: Failed to create socket" << std::endl;
    close_socket(sockfd);
  }
  return sockfd;
}

// Create server socket and set address struct
bool Network::create_server_socket(int &server_sockfd,
                                   struct sockaddr_in &server_addr,
                                   const char *ip, int port) {
  if (server_sockfd > 0) {
    Network::close_socket(server_sockfd);
  }

  server_sockfd = Network::create_socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  if (server_sockfd < 0) {
    std::cerr << "Error: Failed to create server socket " << strerror(errno)
              << std::endl;
    Network::close_socket(server_sockfd);
    return false;
  }
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = inet_addr(ip);
  server_addr.sin_port = htons(port);
  return true;
}

// Create client and set server adress struct
int Network::create_client_socket(int &client_sockfd) {
  if (client_sockfd != 0) {
    close_socket(client_sockfd);
  }
  client_sockfd = create_socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  if (client_sockfd < 0) {
    std::cerr << "Error: Failed to create client socket " << strerror(errno)
              << std::endl;
  }
  return client_sockfd;
}

// bind to a port
bool Network::bind_to_port(int port, int &server_sockfd,
                           struct sockaddr_in &server_addr) {
  server_addr.sin_port = htons(port);
  try {
    if (bind(server_sockfd, reinterpret_cast<struct sockaddr *>(&server_addr),
             sizeof(server_addr)) < 0) {
      // Check if the error is "Address already in use"
      if (errno == EADDRINUSE) {
        std::cerr << "Error: Address already in use" << std::endl;
        Network::close_socket(server_sockfd);
        return false;
      }
      // For other errors, throw an exception
      throw std::runtime_error(std::string("Error: Failed to bind: ") +
                               strerror(errno));
    }
    std::cout << "Server started on port: " << port << std::endl;
    return true;
  } catch (const std::exception &ex) {
    std::cerr << ex.what() << std::endl;
    Network::close_socket(server_sockfd);
    return false;
  }
}

void parse_packet(unsigned char *packet, uint32_t *seq, uint32_t *ack,
                  std::optional<struct sockaddr_in> &source) {
  struct iphdr *iph = reinterpret_cast<struct iphdr *>(packet);
  unsigned short iphdrlen = iph->ihl * 4;

  struct tcphdr *tcph = reinterpret_cast<struct tcphdr *>(packet + iphdrlen);
  if (source) {
    // read source ip address
    source->sin_addr.s_addr = iph->saddr;
    // read source port
    source->sin_port = tcph->source;
  }
  // read sequence number
  uint32_t seq_num = tcph->seq;
  // read acknowledgement number
  uint32_t ack_num = tcph->ack_seq;
  *seq = ntohl(seq_num);
  *ack = ntohl(ack_num);
  printf("sequence number: %lu\n", (unsigned long)*seq);
  printf("acknowledgement number: %lu\n", (unsigned long)*seq);
}

unsigned short Network::checksum(void *buffer, unsigned len) {
  unsigned short *buf = (unsigned short *)buffer;
  unsigned int sum = 0;
  unsigned short result;

  for (sum = 0; len > 1; len -= 2)
    sum += *buf++;

  if (len == 1)
    sum += *(unsigned char *)buf;

  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  result = ~sum;
  return result;
}

// Listen for incoming connections
bool Network::listen_client(int &server_sockfd, int numcl,
                            struct sockaddr_in &server_addr,
                            struct sockaddr_in &client_addr) {
  std::cout << "Listening for incoming connection..." << std::endl;
  unsigned char syn_req[DATAGRAM_SIZE];
  uint32_t seq_num, ack_num;
  // Define the duration for which the loop should run
  auto duration = std::chrono::minutes(5);
  // Get the start time
  auto start_time = std::chrono::steady_clock::now();
  // Calculate the end time
  auto end_time = start_time + duration;
  ssize_t bytes_recv = 0;
  while (std::chrono::steady_clock::now() < end_time) {
    bytes_recv += receive_packet(server_sockfd, &syn_req, DATAGRAM_SIZE);
    if (bytes_recv > 0)
      break;
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }
  // Read ip,tcp headers to acknowledge client
  if (bytes_recv > 0) {
    std::cout << "Received SYN" << std::endl;
    Network::parse_packet(syn_req, client_addr, &seq_num, &ack_num);
    return true;
  } else {
    std::cout << "Client connection timeout" << std::endl;
    return false;
  }
}

// Make connection request
bool Network::connect_to_server(int &client_sockfd,
                                struct sockaddr_in &client_addr,
                                struct sockaddr_in &server_addr, const char *ip,
                                int port) {
  //  Get server's ip and port number
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);
  server_addr.sin_addr.s_addr = inet_addr(ip);
  // Try to connect to server
  // send SYN until received SYN-ACK or TIMEOUT
  int wait_duration = 5; // in seconds
  unsigned char *packet;
  unsigned char response[DATAGRAM_SIZE];
  int packet_size;
  uint32_t seq_num, ack_num;
  Network::create_syn_packet(&client_addr, &server_addr, &packet, &packet_size);
  while (true) {
    std::this_thread::sleep_for(std::chrono::seconds(wait_duration));
    Network::send_packet(client_sockfd, packet, packet_size, &server_addr);
    ssize_t bytes_recv =
        Network::receive_packet(client_sockfd, response, sizeof(response));
    wait_duration += 5;
    if (wait_duration == 120) {
      std::cout << "Connection timeout" << std::endl;
      return false;
    }
    if (bytes_recv > 0)
      break;
    Network::parse_packet(response, server_addr, &seq_num, &ack_num);
  }

  return true;
}

// Accept incoming connections
int Network::accept_connection(int &server_sockfd,
                               struct sockaddr_in server_addr,
                               struct sockaddr_in client_addr) {
  // send ACK packet
  unsigned char *packet;
  int packet_size;
  Network::create_ack_packet(&server_addr, &client_addr, 0, 1, &packet,
                             &packet_size);
  Network::send_packet(server_sockfd, packet, packet_size, &client_addr);
  std::cout << "Sent SYN-ACK" << std::endl;
  return 0;
}

ssize_t Network::send_packet(int sockfd, void *packet, size_t packet_len,
                             struct sockaddr_in *dest_addr) {
  ssize_t bytes_sent =
      sendto(sockfd, packet, packet_len, 0, (struct sockaddr *)dest_addr,
             sizeof(struct sockaddr_in));
  if (bytes_sent < 0) {
    std::cerr << "Error sending raw packet: " << strerror(errno) << std::endl;
  }
  return bytes_sent;
}

ssize_t Network::receive_packet(int sockfd, void *buffer, size_t buffer_len) {
  struct sockaddr_in src_addr;
  socklen_t addr_len = sizeof(src_addr);
  ssize_t bytes_received = recvfrom(sockfd, buffer, buffer_len, 0,
                                    (struct sockaddr *)&src_addr, &addr_len);
  if (bytes_received < 0) {
    std::cerr << "Error receiving raw packet: " << strerror(errno) << std::endl;
    return -1;
  }
  return bytes_received;
}

void Network::close_socket(int socket_fd) {
  close(socket_fd);
  // std::cout << "Socket was closed" << std::endl;
}
