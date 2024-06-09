#include "proxy.hpp"

Proxy::Proxy(const std::string &prx_ip, int prx_port, const std::string &srv_ip,
             int srv_port)
    : Client(prx_ip, srv_ip, srv_port), Server(prx_ip, prx_port),
      prx_ip(std::move(prx_ip)), prx_port(prx_port), srv_ip(std::move(srv_ip)),
      srv_port(srv_port), threadPool(std::make_shared<ThreadPool>(2)) {}

Proxy::~Proxy() {
  Client::~Client();
  Server::~Server();
  Network::close_socket(this->prx_clt_sockfd);
  Network::close_socket(this->prx_srv_sockfd);
}

// capture packet destined to server, do the funny with packet
void Proxy::cap_packet(std::unique_ptr<unsigned char[]> &packet,
                       struct sockaddr_in &source) {

  auto request = std::make_unique<unsigned char[]>(DATAGRAM_SIZE);
  Network::receive_packet(prx_srv_sockfd, request.get(), DATAGRAM_SIZE,
                          srv_addr);
}
void handle_client() {
  // FIXME: handle client with server's methods
}
void handle_server() {
  // FIXME: handle server with client's methods
}

void Proxy::relay_data() {
  // FIXME: implement changing packet and forwarding
}
