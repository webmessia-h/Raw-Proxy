#include "server.hpp"
#include <chrono>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <thread>

Server::Server(const std::string ip, const int port)
    : ip(std::move(ip)), port(port),
      thrd_pool(std::make_shared<ThreadPool>(4)) {}

Server::~Server() { Network::close_socket(this->server_sockfd); }

// Initialize and set-up the server
void Server::launch() {
  if (!Network::create_server_socket(this->server_sockfd, this->srv_addr,
                                     this->ip.c_str(), this->port) ||
      !Network::bind_to_port(this->port, server_sockfd, srv_addr)) {
    return;
  }
  // now we need them for each new socket :)
  // setuid(getuid()); // no need in sudo privileges anymore
  return;
}

// Listen and accept connection
bool Server::accept() {
  for (;;) {

    if (Network::listen_client(server_sockfd, 4, srv_addr, clients))
      // create new socket for each connection
      Network::create_server_socket(this->comn_sockfd, srv_addr, ip.c_str(),
                                    port);
    // accept connection on a new socket
    if (Network::accept_connection(comn_sockfd, srv_addr, clients)) {
      // handle client on other thread
      thrd_pool->enqueue(
          [this]() { handle_client(clients.back(), comn_sockfd); });
      // wait until thread gets copy of socket and client address and then erase
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      clients.pop_back();
      comn_sockfd = 0;
    }
  }
  return true;
}

void Server::handle_client(struct sockaddr_in client, int comn_sockfd) {
  for (;;) {
    std::string data;
    this->receive_request(data, client, comn_sockfd);
    this->send_response();
  }
}

void Server::receive_request(std::string &data, struct sockaddr_in &client,
                             int &comn_sockfd) {
  auto request = std::make_unique<unsigned char[]>(DATAGRAM_SIZE);
  struct tcphdr *tcph;
  struct iphdr *iph;
  int src_port{0};
  do {
    Network::receive_packet(comn_sockfd, request.get(), DATAGRAM_SIZE,
                            srv_addr);
    iph = reinterpret_cast<struct iphdr *>(request.get());
    tcph = reinterpret_cast<struct tcphdr *>(
        (reinterpret_cast<char *>(request.get() + iph->ihl * 4)));

    src_port = tcph->source;
  } while (src_port != client.sin_port);

  Network::parse_packet(request, &seq_num, &ack_num, *clients.data());
  data.assign(reinterpret_cast<const char *>(request.get()));
  std::cout << "\tpayload: " << data;
}

void Server::send_response() {
  /* TODO: idk if it belogs here*/
  if (this->seq_num != 0)
    this->seq_num++;
  /*---------------------------*/
  std::string resp;
  std::cout << "\n\nresponse: ";
  std::getline(std::cin, resp);
  std::unique_ptr<unsigned char[]> packet;
  int packet_size{0};
  Network::create_data_packet(&srv_addr, clients.data(), seq_num, ack_num, resp,
                              packet, &packet_size);
  Network::send_packet(server_sockfd, packet.get(), packet_size,
                       *clients.data());
}
