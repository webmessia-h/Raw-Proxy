#include "client.hpp"
int main(int argc, char *argv[]) {

  if (argc != 4) {
    std::cerr << "Usage: " << argv[0] << "<self_ip> <proxy_ip> <proxy_port>"
              << std::endl;
    return 1;
  }

  const std::string s_ip = argv[1];
  const std::string ip = argv[2];
  int port = std::stoi(argv[3]);

  Client *clt = new Client(s_ip, ip, port);

  /**
   * @brief On successful connection // cl->SYN - srv->ACK - cl->ACK //
   * start sending requests and receive responses in an infinite loop
   */
  if (clt->connect()) {
    for (;;) {
      std::string msg;
      std::cout << "\n\nmessage for server: ";
      std::getline(std::cin, msg);
      clt->send_request(msg);

      std::string resp;
      clt->receive_response(resp);
      std::cout << "\tpayload: " << resp;
    }
  }

  delete clt;
  clt = nullptr;
  return 0;
}
