#include "server.hpp"
#include "../shared_resources/include/network.hpp"
#include "../shared_resources/include/platform.hpp"
#include <cerrno>
#include <cstring>
#include <memory>

Server::Server(const std::string ip, const int port)
    : ip(std::move(ip)), port(port) {}

Server::~Server() {
  Network::close_socket(this->server_sockfd);
  Network::close_socket(this->communication_sockfd);
}

// Initialize and set-up the server
void Server::launch() {
  if (!Network::create_server_socket(server_sockfd, this->srv_addr,
                                     this->ip.c_str(), this->port) ||
      !Network::bind_to_port(this->port, this->server_sockfd, this->srv_addr)) {
    return;
  }
  return;
}

// Listen and accept connection
bool Server::accept() {
  if (!Network::listen_client(server_sockfd, 1, srv_addr, this->clt_addr) ||
      !Network::accept_connection(server_sockfd, srv_addr, clt_addr)) {
    return false;
  }
  // setuid(getuid()); // no need in sudo privileges anymore
  return true;
}

void Server::receive_request(std::string &data) {
  std::unique_ptr<unsigned char[]> request;
  ssize_t packet_size{0};

  packet_size +=
      Network::receive_packet(server_sockfd, &request, DATAGRAM_SIZE, srv_addr);
  struct iphdr *iph = reinterpret_cast<struct iphdr *>(&request);

  struct tcphdr *tcph =
      reinterpret_cast<struct tcphdr *>(request.get() + iph->ihl * 4);

  if (tcph->dest == htons(port)) {
    data.assign(reinterpret_cast<char *>(tcph + 1),
                packet_size - sizeof(struct iphdr) - sizeof(struct tcphdr));
    std::cout << "I'M ALIVE!!!!" << std::endl;
  }

  // TODO: perform checksum comparation and log into console
}

void Server::send_response(const std::string &data) {
  std::unique_ptr<unsigned char[]> packet;
  int packet_size{0};
  Network::create_data_packet(&srv_addr, &clt_addr, seq_num, ack_num, data,
                              packet, &packet_size);
  Network::send_packet(server_sockfd, &packet, packet_size, &clt_addr);
}
