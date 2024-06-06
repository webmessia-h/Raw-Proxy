#include "client.hpp"
#include "../shared_resources/include/network.hpp"

Client::Client(const std::string ip, const int port)
    : ip(std::move(ip)), port(port) {}

Client::~Client() { Network::close_socket(this->client_sockfd); }

void Client::connect() {
  // create client communication socket
  if (!Network::create_client_socket(this->client_sockfd))
    return;
  // connect client socket to server
  if (!Network::connect_to_server(client_sockfd, srv_addr, this->ip.c_str(),
                                  this->port))
    return;
  setuid(getuid()); // no need in sudo privileges anymore
  return;
}

void Client::send_request(const std::string &data) {
  unsigned char *packet;
  int packet_size{0};
  Network::create_data_packet(&this->clt_addr, &srv_addr, data, &packet,
                              &packet_size);
  Network::send_raw_packet(client_sockfd, packet, packet_size, &srv_addr);
}

void Client::receive_response(std::string &data) {
  unsigned char buffer[1024];
  ssize_t data_size =
      recvfrom(client_sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
  if (data_size < 0) {
    std::cerr << "Error receiving packet" << std::endl;
    return;
  }

  struct iphdr *iph = reinterpret_cast<struct iphdr *>(buffer);
  struct tcphdr *tcph =
      reinterpret_cast<struct tcphdr *>(buffer + iph->ihl * 4);

  if (tcph->dest == htons(port)) {
    data.assign(reinterpret_cast<char *>(tcph + 1),
                data_size - sizeof(struct iphdr) - sizeof(struct tcphdr));
  }

  // TODO: strip data and log into console
}
