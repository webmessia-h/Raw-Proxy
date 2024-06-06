#include "../include/network.hpp"

#include <cerrno>
#include <iostream>
#include <netinet/ip.h>
#include <string.h>
#include <unistd.h>

// TODO: move to helpers
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

// Create connection request packet
void create_syn_packet(struct sockaddr_in *src, struct sockaddr_in *dst,
                       unsigned char **packet, int *packet_size);
// Create ACK packet
void create_ack_packet(struct sockaddr_in *src, struct sockaddr_in *dst,
                       int32_t seq, int32_t ack_seq, unsigned char **packet,
                       int *packet_size);
// Read sequence
void read_seq_and_ack(const char *packet, uint32_t *seq, uint32_t *ack);

void Network::create_data_packet(struct sockaddr_in *src,
                                 struct sockaddr_in *dst,
                                 const std::string &data,
                                 unsigned char **packet, int *packet_size) {
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
  iph->check = 0; // correct calculation follows later
  iph->saddr = src->sin_addr.s_addr;
  iph->daddr = dst->sin_addr.s_addr;

  // TCP header configuration
  tcph->source = src->sin_port;
  tcph->dest = dst->sin_port;
  tcph->seq = htonl(0);
  tcph->ack_seq = htonl(0);
  tcph->doff = 10; // tcp header size
  tcph->fin = 0;
  tcph->syn = 0;
  tcph->rst = 0;
  tcph->psh = 1;
  tcph->ack = 1;
  tcph->urg = 0;
  tcph->check = 0;            // will calculate later
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

// Create server socket
bool Network::create_server_socket(int &server_sockfd,
                                   struct sockaddr_in &server_addr,
                                   const char *ip, int port) {
  if (server_sockfd > 0) {
    Network::close_socket(server_sockfd);
  }

  server_sockfd = Network::create_socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
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

// Create client
int Network::create_client_socket(int &client_sockfd) {
  if (client_sockfd != 0) {
    close_socket(client_sockfd);
  }
  client_sockfd = create_socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (client_sockfd < 0) {
    std::cerr << "Error: Failed to create client socket " << strerror(errno)
              << std::endl;
  }

  return client_sockfd;
}

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
    // std::cout << "Server started on port: " << port << std::endl;
    return true;
  } catch (const std::exception &ex) {
    std::cerr << ex.what() << std::endl;
    Network::close_socket(server_sockfd);
    return false;
  }
}

// Listen for incoming connections
bool Network::listen_client(int &server_sockfd, int numcl) {
  // FIXME: there is no 'listen' on SOCK_RAW, implement another method
  // just `recvfrom()` in a infinite loop
  if (listen(server_sockfd, numcl) < 0) {
    std::cerr << "Error: Failed to listen " << strerror(errno) << std::endl;
    Network::close_socket(server_sockfd);
    return false;
  }
  // std::cout << "Listening for incoming connection" << std::endl;
  return true;
}

void Network::handshake(int &socket_fd, sockaddr_in *dest_addr) {
  /*FIXME:  just encapsulate everything we need for the handshake
    std::cout.write(msg, strlen(msg));
    std::cout << "\n";
    return;
  */
}

// Make connection request
bool Network::connect_to_server(int &client_sockfd,
                                struct sockaddr_in &server_addr, const char *ip,
                                int port) {
  //  Get server's ip and port number
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);
  server_addr.sin_addr.s_addr = inet_addr(ip);
  // Try to connect to server
  // FIXME: there is no `connect()` just fill the server addr and perform
  // handshake
  if (connect(client_sockfd, reinterpret_cast<sockaddr *>(&server_addr),
              sizeof(server_addr)) < 0) {
    // Failed to connect
    std::cerr << "Error: Client failed to connect to:"
              << inet_ntoa(server_addr.sin_addr) << " on port: " << port << "\t"
              << strerror(errno) << std::endl;
    close_socket(client_sockfd);
    return false;
  }
  return true;
}

// Accept incoming connections
int Network::accept_connection(int &server_sockfd, int &communication_sockfd) {
  // Create communication socket
  struct sockaddr_in client_addr;
  socklen_t client_addr_len = sizeof(client_addr);
  // FIXME: there is no `accept()` just send SYN ACK
  communication_sockfd =
      accept(server_sockfd, reinterpret_cast<struct sockaddr *>(&client_addr),
             &client_addr_len);
  if (communication_sockfd < 0) {
    std::cerr << "Error: Connection was not accepted " << strerror(errno)
              << std::endl;
    return -1;
  }
  return communication_sockfd;
}

ssize_t Network::send_raw_packet(int sockfd, void *packet, size_t packet_len,
                                 struct sockaddr_in *dest_addr) {
  ssize_t bytes_sent =
      sendto(sockfd, packet, packet_len, 0, (struct sockaddr *)dest_addr,
             sizeof(struct sockaddr_in));
  if (bytes_sent < 0) {
    std::cerr << "Error sending raw packet: " << strerror(errno) << std::endl;
  }
  return bytes_sent;
}

ssize_t Network::receive_raw_packet(int sockfd, void *buffer,
                                    size_t buffer_len) {
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
