#include "client.hpp"

int main(int argc, char *argv[]) {
  if (argc != 3) {
    std::cerr << "Usage: " << argv[0] << "<server_ip> <port_number>"
              << std::endl;
    return 1;
  }

  const std::string ip = argv[1];
  int port = std::stoi(argv[2]);

  Client *cl = new Client(ip, port);
  cl->connect();
  std::string msg;
  std::cout << "Message for server";
  std::cin >> msg;
  cl->encrypt_and_send(msg);
  cl->~Client();
  delete cl;
  cl = nullptr;
  return 0;
}
