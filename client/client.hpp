// client
#pragma once
#include "../shared_resources/include/network.hpp"
#include "../shared_resources/include/platform.hpp"
#include <string>
class Client {

public:
  Client(const std::string s_ip, const std::string ip, const int port);
  ~Client();

  void connect();
  // TODO: maybe implement some authentication
  //  so the proxy ain't meaningless
  void send_request(const std::string &data);
  void receive_response();

private:
  std::string self_ip;
  std::string ip;

  int client_sockfd, port;
  uint32_t seq_num, ack_num = 0;
  struct sockaddr_in srv_addr, clt_addr;

  unsigned char session_key[16];

  unsigned char iv[16] = "initialvector11";
};
