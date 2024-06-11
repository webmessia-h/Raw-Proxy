#include "proxy.hpp"
#include <memory>

Proxy::Proxy(const std::string &prx_ip, int prx_port, const std::string &srv_ip,
             int srv_port)
    : Client(prx_ip, srv_ip, srv_port), Server(prx_ip, prx_port),
      prx_ip(std::move(prx_ip)), prx_port(prx_port), srv_ip(std::move(srv_ip)),
      srv_port(srv_port), threadPool(std::make_shared<ThreadPool>(2)) {}

Proxy::~Proxy() {
  Client::~Client();
  Server::~Server();
}

// capture packet destined to server, do the funny with packet
void Proxy::receive_request(std::string &data) {

  // idk decided to override base class method (server)
  auto request = std::make_unique<unsigned char[]>(DATAGRAM_SIZE);
  Network::receive_packet(server_sockfd, request.get(), DATAGRAM_SIZE,
                          Server::srv_addr);
  struct iphdr *iph = reinterpret_cast<struct iphdr *>(request.get());
  unsigned short iphdrlen = iph->ihl * 4;
  struct tcphdr *tcph =
      reinterpret_cast<struct tcphdr *>(request.get() + iphdrlen);
  unsigned short tcphdrlen = tcph->doff * 4;
  // pretend we are the client
  std::cout << "Captured request\n" << std::endl;
  this->Server::clt_addr.sin_port = tcph->source;
  tcph->source = Client::clt_addr.sin_port;
  tcph->dest = Client::srv_addr.sin_port;
  iph->saddr = Client::clt_addr.sin_addr.s_addr;
  iph->daddr = Client::srv_addr.sin_addr.s_addr;
  // Determine payload size
  unsigned int payload_size = ntohs(iph->tot_len) - (iphdrlen + tcphdrlen);
  // TODO: FIX BUG WITH CHANGING PACKET PAYLOAD ONLY ONCE
  srand((time(0)));
  if (rand() % 2 == 0) {
    // change payload
    if (payload_size > 0 && payload_size < DATAGRAM_SIZE) {
      // modify packet
      const std::string nval = " hehe ԅ(≖‿≖ԅ)";
      std::copy(nval.begin(), nval.end(), request.get() + iphdrlen + tcphdrlen);
      Network::send_packet(client_sockfd, request.get(),
                           (iphdrlen + tcphdrlen + nval.size()),
                           Client::srv_addr);
    }
  } else {
    Network::send_packet(client_sockfd, request.get(),
                         (iphdrlen + tcphdrlen + payload_size),
                         Client::srv_addr);
  }
  return;
}

void Proxy::receive_response(std::string &data) {
  // idk decided to override base class method (client)
  auto request = std::make_unique<unsigned char[]>(DATAGRAM_SIZE);
  ssize_t bytes = Network::receive_packet(client_sockfd, request.get(),
                                          DATAGRAM_SIZE, Client::clt_addr);
  std::cout << "Captured response\n" << std::endl;
  struct iphdr *iph = reinterpret_cast<struct iphdr *>(request.get());
  unsigned short iphdrlen = iph->ihl * 4;
  struct tcphdr *tcph =
      reinterpret_cast<struct tcphdr *>(request.get() + iphdrlen);
  unsigned short tcphdrlen = tcph->doff * 4;
  unsigned int payload_size = ntohs(iph->tot_len) - (iphdrlen + tcphdrlen);
  // pretend we are the server
  tcph->source = Server::srv_addr.sin_port;
  tcph->dest = Server::clt_addr.sin_port;
  iph->saddr = Server::srv_addr.sin_addr.s_addr;
  iph->daddr = Server::clt_addr.sin_addr.s_addr;
  Network::send_packet(server_sockfd, request.get(),
                       (iphdrlen + tcphdrlen + payload_size), Server::clt_addr);
  // TODO: would be good to recalculate checksum so client doesn't panic
  return;
}
