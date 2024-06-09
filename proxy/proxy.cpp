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
  // change the destination port to real server port
  tcph->dest = Client::srv_addr.sin_port;
  // Determine payload size
  unsigned int payload_size = ntohs(iph->tot_len) - (iphdrlen + tcphdrlen);

  // TODO: FIX BUG WITH CHANGING PACKET PAYLOAD WHERE PAYLOAD AIN'T CHANGED
  // AFTER THE FIRST TIME condition to change payload
  srand((time(nullptr)));
  if (rand() % 2 == 0) {
    // change payload
    if (payload_size > 0 && payload_size < DATAGRAM_SIZE) {
      auto payload = std::make_unique<unsigned char[]>(payload_size);
      memcpy(payload.get(), request.get() + (iphdrlen + tcphdrlen),
             payload_size);
      // modify packet
      std::string nval = " hehe ԅ(≖‿≖ԅ)";
      if (payload_size + nval.size() < DATAGRAM_SIZE) {
        std::copy(nval.begin(), nval.end(), payload.get() + payload_size);
        size_t npayload = payload_size + nval.size();
        std::cout << npayload;

        memcpy(request.get() + iphdrlen + tcphdrlen, payload.get(), npayload);
        Network::send_packet(client_sockfd, request.get(),
                             (iphdrlen + tcphdrlen + npayload),
                             Client::srv_addr);
      } else {
        std::cout << "\rbuffer overflow";
      }
    }
  } else {
    Network::send_packet(client_sockfd, request.get(),
                         (iphdrlen + tcphdrlen + payload_size),
                         Client::srv_addr);
  }
}
