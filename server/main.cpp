#include "server.hpp"

int main(int argc, char *argv[]) {
  if (argc != 3) {
    std::cerr << "Usage: " << argv[0] << "<server_ip> <port_number>"
              << std::endl;
    return 1;
  }

  const char *ip = argv[1];
  int port = std::stoi(argv[2]);

  Server *srv = new Server(ip, port);

  srv->launch();

  if (srv->accept()) {
    for (;;) {
      std::string req;
      srv->receive_request(req);
      std::cout << "\tpayload: " << req;

      std::string resp;
      std::cout << "\n\nresponse: ";
      std::getline(std::cin, resp);
      srv->send_response(resp);
    }
  }
  srv->~Server();
  delete srv;
  srv = nullptr;
  return 0;
}
