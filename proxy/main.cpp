#include "proxy.hpp"

int main(int argc, char *argv[]) {
  if (argc != 5) {
    std::cerr << "Usage: " << argv[0]
              << "<proxy_ip> <proxy_port> <server_ip> <port_number>"
              << std::endl;
    return 1;
  }

  const std::string prx_ip = argv[1];
  int prx_port = std::stoi(argv[2]);
  const std::string srv_ip = argv[3];
  int srv_port = std::stoi(argv[4]);

  Proxy *prx = new Proxy(prx_ip, prx_port, srv_ip, srv_port);
  prx->launch();
  prx->accept();
  prx->connect();
  prx->relay_data();
  std::string msg;
  std::cout << "Message for server";
  std::cin >> msg;
  prx->~Proxy();
  delete prx;
  prx = nullptr;
  return 0;
}