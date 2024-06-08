#include "client.hpp"
#include "../shared_resources/include/network.hpp"
#include <memory>

Client::Client(const std::string s_ip, const std::string ip, const int port)
    : self_ip(std::move(s_ip)), ip(std::move(ip)), port(port) {}

Client::~Client() { Network::close_socket(this->client_sockfd); }

bool Client::connect() {
  // create client communication socket
  if (!Network::create_client_socket(this->client_sockfd, this->clt_addr,
                                     this->self_ip.c_str()))
    return false;
  // connect client socket to server
  if (!Network::connect_to_server(client_sockfd, clt_addr, srv_addr,
                                  this->ip.c_str(), this->port, &seq_num,
                                  &ack_num))
    return false;
  setuid(getuid()); // no need in sudo privileges anymore
  return true;
}

void Client::send_request(const std::string &data) {
  /* TODO: idk if it belogs here*/
  if (this->seq_num != 0)
    this->seq_num++;
  /*---------------------------*/
  std::unique_ptr<unsigned char[]> packet;
  int packet_size{0};
  Network::create_data_packet(&clt_addr, &srv_addr, seq_num, ack_num, data,
                              packet, &packet_size);
  Network::send_packet(client_sockfd, packet.get(), packet_size, &srv_addr);
}

void Client::receive_response() {
  std::cout << "into receive response\n";
  auto response = std::make_unique<unsigned char[]>(DATAGRAM_SIZE);
  Network::receive_packet(client_sockfd, response.get(), DATAGRAM_SIZE,
                          clt_addr);

  Network::parse_packet(response, &seq_num, &ack_num, srv_addr);
  std::cout.write(reinterpret_cast<const char *>(response.get()),
                  strlen(reinterpret_cast<const char *>(response.get())));
  // TODO: strip data and log into console
}
