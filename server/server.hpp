// server
#pragma once
#include "../shared_resources/include/network.hpp"
#include "../shared_resources/include/threadpool.hpp"
#include <iostream>
#include <netinet/in.h>
#include <string>

class Server {
public:
  Server(const std::string ip, const int port);
  ~Server();

  void launch();
  bool accept();
  // TODO: make send/recv smarter
  void send_response(const std::string &data);
  virtual void receive_request(std::string &data);

protected:
  int server_sockfd;
  struct sockaddr_in srv_addr;
  struct sockaddr_in clt_addr;

private:
  std::string ip;
  int port;

  uint32_t seq_num, ack_num = 0;

  std::shared_ptr<ThreadPool> threadPool;
};
