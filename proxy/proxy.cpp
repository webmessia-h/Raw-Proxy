#include "proxy.hpp"
#include <netinet/in.h>

Proxy::Proxy(const std::string &prx_ip, int prx_port, const std::string &srv_ip,
             int srv_port)
    : Client(prx_ip, srv_ip, srv_port), Server(prx_ip, prx_port),
      prx_ip(std::move(prx_ip)), prx_port(prx_port), srv_ip(std::move(srv_ip)),
      srv_port(srv_port) {}

Proxy::~Proxy() {}

void Proxy::handle_client(struct sockaddr_in client, int comn_sockfd) {
  for (;;) {
    std::string data;
    this->receive_request(data, client, comn_sockfd);
    this->receive_response(data, client, comn_sockfd);
  }
}

// capture packet destined to server, do the funny with packet
void Proxy::receive_request(std::string &data, struct sockaddr_in &client,
                            int &comn_sockfd) {

  // idk decided to override base class method (server)
  auto request = std::make_unique<unsigned char[]>(DATAGRAM_SIZE);
  int src_port{0};
  struct iphdr *iph;
  struct tcphdr *tcph;
  unsigned short iphdrlen;
  unsigned short tcphdrlen;
  do {
    Network::receive_packet(comn_sockfd, request.get(), DATAGRAM_SIZE,
                            Server::srv_addr);
    iph = reinterpret_cast<struct iphdr *>(request.get());
    iphdrlen = iph->ihl * 4;
    tcph = reinterpret_cast<struct tcphdr *>(request.get() + iphdrlen);
    tcphdrlen = tcph->doff * 4;
    src_port = tcph->source;
  } while (src_port != client.sin_port);
  // pretend we are the client
  std::cout << "Captured request\n" << std::endl;
  this->Server::clients.data()->sin_port = tcph->source;
  tcph->source = Client::clt_addr.sin_port;
  tcph->dest = Client::srv_addr.sin_port;
  iph->saddr = Client::clt_addr.sin_addr.s_addr;
  iph->daddr = Client::srv_addr.sin_addr.s_addr;
  // TODO: would be good to recalculate checksum at this point
  // Determine payload size
  unsigned int payload_size = ntohs(iph->tot_len) - (iphdrlen + tcphdrlen);
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

void Proxy::receive_response(std::string &data, struct sockaddr_in &client,
                             int &comn_sockfd) {
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
  tcph->dest = client.sin_port;
  iph->saddr = Server::srv_addr.sin_addr.s_addr;
  iph->daddr = client.sin_addr.s_addr;
  Network::send_packet(comn_sockfd, request.get(),
                       (iphdrlen + tcphdrlen + payload_size), client);
  // TODO: would be good to recalculate checksum so client doesn't panic
  return;
}
