// server
#pragma once
#include "../shared_resources/include/network.hpp"
#include "../shared_resources/include/threadpool.hpp"
#include <iostream>
#include <string>

class Server {
public:
  Server(const std::string ip, const int port);
  ~Server();

  void launch();
  bool accept();
  void send_response(const std::string &data);
  void receive_request(std::string &data);

private:
  std::string ip;

  int server_sockfd, port;

  uint32_t seq_num, ack_num = 0;

  struct sockaddr_in srv_addr, clt_addr;

  std::shared_ptr<ThreadPool> threadPool;

  unsigned char session_key[16];
  unsigned char iv[16] = "initialvector11";
};
