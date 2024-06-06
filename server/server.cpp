#include "server.hpp"
#include "../shared_resources/include/network.hpp"
#include "../shared_resources/include/platform.hpp"
#include <cerrno>
#include <cstring>

Server::Server(const std::string ip, const int port)
    : ip(std::move(ip)), port(port) {}

Server::~Server() {
  Network::close_socket(this->server_sockfd);
  Network::close_socket(this->communication_sockfd);
}

// Initialize and set-up the server
void Server::launch() {
  if (!Network::create_server_socket(server_sockfd, srv_addr, this->ip.c_str(),
                                     this->port) ||
      !Network::bind_to_port(this->port, this->server_sockfd, this->srv_addr)) {
    return;
  }
  return;
}

// Listen and accept connection
bool Server::accept() {
  if (!Network::listen_client(server_sockfd, 1) ||
      !Network::accept_connection(server_sockfd, this->communication_sockfd)) {
    return false;
  }
  setuid(getuid()); // no need in sudo privileges anymore
  return true;
}

void Server::receive_request(std::string &data) {
  unsigned char buffer[1024];
  ssize_t data_size =
      recvfrom(communication_sockfd, buffer, sizeof(buffer), 0, NULL, NULL);
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

  // TODO: perform checksum comparation and log into console
}

void Server::send_response(const std::string &data) {
  unsigned char *packet;
  int packet_size{0};
  Network::create_data_packet(&this->srv_addr, &clt_addr, data, &packet,
                              &packet_size);
  Network::send_raw_packet(communication_sockfd, packet, packet_size,
                           &clt_addr);
}
