#pragma once
#include "../client/client.hpp"
#include "../server/server.hpp"
#include "../shared_resources/include/network.hpp"
#include "../shared_resources/include/threadpool.hpp"
#include <netinet/in.h>
#include <sys/socket.h>

class Proxy : public Server, public Client {
public:
  Proxy(const std::string &prx_ip, int prx_port, const std::string &server_ip,
        int server_port);
  ~Proxy();

  // merge two methods below
  void handle_client(struct sockaddr_in client, int comn_sockfd) override;
  // Do the funny (intercept packets, change source and destination adress, with
  // 50% chance change packet payload)
  void receive_request(std::string &data, struct sockaddr_in &client,
                       int &comn_sockfd) override;
  // forward from server to client
  void receive_response(std::string &data, struct sockaddr_in &client,
                        int &comn_sockfd);

private:
  std::string prx_ip, srv_ip;
  int srv_port, prx_port;
};
