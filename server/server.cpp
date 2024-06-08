#include "server.hpp"
#include "../shared_resources/include/network.hpp"
#include "../shared_resources/include/platform.hpp"
#include <cerrno>
#include <cstring>
#include <memory>

Server::Server(const std::string ip, const int port)
    : ip(std::move(ip)), port(port) {}

Server::~Server() { Network::close_socket(this->server_sockfd); }

// Initialize and set-up the server
void Server::launch() {
  if (!Network::create_server_socket(server_sockfd, this->srv_addr,
                                     this->ip.c_str(), this->port) ||
      !Network::bind_to_port(this->port, this->server_sockfd, this->srv_addr)) {
    return;
  }
  setuid(getuid()); // no need in sudo privileges anymore
  return;
}

// Listen and accept connection
bool Server::accept() {
  if (!Network::listen_client(server_sockfd, 1, srv_addr, this->clt_addr) ||
      !Network::accept_connection(server_sockfd, srv_addr, clt_addr)) {
    return false;
  }
  return true;
}

void Server::receive_request(std::string &data) {
  auto request = std::make_unique<unsigned char[]>(DATAGRAM_SIZE);
  ssize_t packet_size{0};
  packet_size += Network::receive_packet(server_sockfd, request.get(),
                                         DATAGRAM_SIZE, srv_addr);

  Network::parse_packet(request, &seq_num, &ack_num, clt_addr);
  data.assign(reinterpret_cast<const char *>(request.get()));
  // TODO: perform checksum comparation and log into console
}

void Server::send_response(const std::string &data) {
  /* TODO: idk if it belogs here*/
  if (this->seq_num != 0)
    this->seq_num++;
  /*---------------------------*/
  std::unique_ptr<unsigned char[]> packet;
  int packet_size{0};
  Network::create_data_packet(&srv_addr, &clt_addr, seq_num, ack_num, data,
                              packet, &packet_size);
  Network::send_packet(server_sockfd, &packet, packet_size, &clt_addr);
}
