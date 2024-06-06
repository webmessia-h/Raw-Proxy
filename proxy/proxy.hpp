#include "../client/client.hpp"
#include "../server/server.hpp"
#include "../shared_resources/include/network.hpp"
#include "../shared_resources/include/threadpool.hpp"
#include <cerrno>
#include <iostream>

class Proxy : public Server, public Client {
public:
  Proxy(const std::string &prx_ip, int prx_port, const std::string &server_ip,
        int server_port);
  ~Proxy();

  // TODO: implement handling here,concurrent approach maybe
  void handle_client();
  void handle_server();
  // TODO: split this into separate methods
  void relay_data();

private:
  std::string prx_ip, srv_ip;
  int prx_srv_sockfd, prx_clt_sockfd, srv_port, prx_port;
  struct sockaddr_in srv_addr, clt_addr;
  std::shared_ptr<ThreadPool> threadPool;
  unsigned char session_key[16];
  unsigned char iv[16] = "initialvector11";
};
