#include "client.hpp"
#include "../shared_resources/include/network.hpp"
#include <memory>

Client::Client(const std::string s_ip, const std::string ip, const int port)
    : self_ip(std::move(s_ip)), ip(std::move(ip)), port(port) {}

Client::~Client() { Network::close_socket(this->client_sockfd); }

void Client::connect() {
  // create client communication socket
  if (!Network::create_client_socket(this->client_sockfd, this->clt_addr,
                                     this->self_ip.c_str()))
    return;
  // connect client socket to server
  if (!Network::connect_to_server(client_sockfd, clt_addr, srv_addr,
                                  this->ip.c_str(), this->port, &seq_num,
                                  &ack_num))
    return;
  setuid(getuid()); // no need in sudo privileges anymore
  return;
}

void Client::send_request(const std::string &data) {
  std::unique_ptr<unsigned char[]> packet;
  int packet_size{0};
  Network::create_data_packet(&clt_addr, &srv_addr, seq_num, ack_num, data,
                              packet, &packet_size);
  Network::send_packet(client_sockfd, packet.get(), packet_size, &srv_addr);
}

void Client::receive_response() {
  unsigned char *response;
  Network::receive_packet(this->client_sockfd, &response, DATAGRAM_SIZE,
                          clt_addr);

  Network::parse_packet(response, &seq_num, &ack_num, srv_addr);
  // TODO: strip data and log into console
}
