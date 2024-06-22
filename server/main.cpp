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

  /**
   * @brief If successful setup then
   * accept connections on main thread
   * then pass them to handle_client()
   * each new connection is handled by
   * a thread pool
   */
  if (srv->launch()) {
    if (srv->accept()) {
      // for any additional logic change handle_client() method
    }
  }
  delete srv;
  srv = nullptr;
  return 0;
}
