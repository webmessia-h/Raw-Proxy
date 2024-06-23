// server
#pragma once
#include "../shared_resources/include/network.hpp"
#include "../shared_resources/include/threadpool.hpp"
#include <string>

class Server {
public:
  Server(const std::string ip, const int port);
  virtual ~Server();

  bool launch();
  bool accept();
  virtual void handle_client(struct sockaddr_in client, int comn_sockfd);
  void send_response();
  virtual void receive_request(std::string &data, struct sockaddr_in &client,
                               int &comn_sockfd);

protected:
  int server_sockfd;
  int comn_sockfd;
  struct sockaddr_in srv_addr;
  std::vector<struct sockaddr_in> clients;

private:
  std::string ip;
  int port;

  uint32_t seq_num, ack_num = 0;

  std::shared_ptr<ThreadPool> thrd_pool;
};
