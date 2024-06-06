#include "proxy.hpp"

Proxy::Proxy(const std::string &prx_ip, int prx_port, const std::string &srv_ip,
             int srv_port)
    : Client(srv_ip, srv_port), Server(prx_ip, prx_port),
      prx_ip(std::move(prx_ip)), prx_port(prx_port), srv_ip(std::move(srv_ip)),
      srv_port(srv_port), threadPool(std::make_shared<ThreadPool>(2)) {}

Proxy::~Proxy() {
  Client::~Client();
  Server::~Server();
}

void handle_client() {
  // FIXME: handle client with server's methods
}
void handle_server() {
  // FIXME: handle server with client's methods
}

void Proxy::relay_data() {
  while (true) {
    // Accept client connection
    int comm_sockfd =
        Network::accept_connection(prx_clt_sockfd, prx_clt_sockfd);
    if (comm_sockfd < 0) {
      std::cerr << "Failed to accept client connection" << std::endl;
      continue;
    }
  }
  unsigned char ciphertext[128];
  unsigned char plaintext[128];
  unsigned char decryptedtext[128];
  int decryptedtext_len, ciphertext_len;

  // FIXME: implement just changing packet and forwarding
}
