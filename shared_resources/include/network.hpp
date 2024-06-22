// network
#pragma once
#include <arpa/inet.h>
#include <chrono>   // for timeouts
#include <cstdint>  // for int_*t types
#include <iostream> // for logging
#include <memory>   // for unique_ptr's
#include <netinet/in.h>
#include <netinet/ip.h>  // For iphdr
#include <netinet/tcp.h> // For tcphdr
#include <string.h>      // for logging with strerror
#include <string>
#include <sys/types.h> // For socket types
#include <thread>      // for timeouts
#include <unistd.h>    // POSIX
#include <vector> // for accepting std::vector<struct sockaddr_in> as parameter

namespace Network {

#define DATAGRAM_SIZE 1460 // standard packet size(length)
#define OPT_SIZE 20        // TCP options size(length)

#define REQUEST_SIZE                                                           \
  (sizeof(struct iphdr) + sizeof(struct tcphdr) +                              \
   OPT_SIZE) // size of typical SYN/ACK-only packet

// pseudo header needed for checksum calculation
struct pseudo_header {
  u_int32_t src_addr;
  u_int32_t dst_addr;
  u_int8_t placeholder;
  u_int8_t protocol;
  u_int16_t tcp_length;
};

/*------------------- PACKET TYPES CONSTRUCTION -----------------------*/
// Create connection request packet
void create_syn_packet(struct sockaddr_in *src, struct sockaddr_in *dst,
                       std::unique_ptr<unsigned char[]> &packet,
                       int *packet_size);
//----------------------------------------------------------------------|
// Create ACK packet
void create_ack_packet(struct sockaddr_in *src, struct sockaddr_in *dst,
                       uint32_t seq, uint32_t ack_seq,
                       std::unique_ptr<unsigned char[]> &packet,
                       int *packet_size);
//----------------------------------------------------------------------|
// Create data packet
void create_data_packet(struct sockaddr_in *src, struct sockaddr_in *dst,
                        uint32_t seq, uint32_t ack_seq, const std::string &data,
                        std::unique_ptr<unsigned char[]> &packet,
                        int *packet_size);
/*--------------------------------------------------------------------*/

//------------------------------------------------------------------------------|

/*----------------  BASIC COMMUNICATEES INITIALIZATION  --------------*/
// Create socket with some logging on exception
int create_socket(int domain, int type, int protocol);
//---------------------------------------------------------------------|
// Initialize server socket
bool create_server_socket(int &server_sockfd, struct sockaddr_in &server_addr,
                          const char *ip, int port);
//---------------------------------------------------------------------|
// Initialize client socket
int create_client_socket(int &client_sockfd, struct sockaddr_in &client_addr,
                         const char *ip);
//---------------------------------------------------------------------|
// Bind server's socket
bool bind_to_port(int port, int &sockfd, struct sockaddr_in &addr);
/*--------------------------------------------------------------------*/

//------------------------------------------------------------------------------|

/*--------------------  COMMUNICATION INTERFACE ----------------------*/
// Read ip, tcp headers, checksum etc.
void parse_packet(std::unique_ptr<unsigned char[]> &packet, uint32_t *seq,
                  uint32_t *ack, struct sockaddr_in &source);
//----------------------------------------------------------------------|
// Calculate checksum of packet
unsigned short checksum(void *buffer, unsigned len);
//----------------------------------------------------------------------|
// Listen for incoming connections
bool listen_client(int &server_sockfd, int numcl,
                   struct sockaddr_in &server_addr,
                   std::vector<struct sockaddr_in> &clients);
//---------------------------------------------------------------------|
// Make connection request
// Send SYN signal and listen for SYN ACK
bool connect_to_server(int &client_sockfd, struct sockaddr_in &client_addr,
                       struct sockaddr_in &server_addr, const char *ip,
                       int port, uint32_t *seq_num, uint32_t *ack_num);
//---------------------------------------------------------------------|
// Accept pending connection request
// Respond to SYN with SYN ACK
int accept_connection(int &server_sockfd, struct sockaddr_in &server_addr,
                      std::vector<struct sockaddr_in> &clients);
//---------------------------------------------------------------------|
// Send raw packet with some logging if exception
ssize_t send_packet(int sockfd, void *packet, size_t packet_len,
                    struct sockaddr_in &dest_addr);
//---------------------------------------------------------------------|
// Receive raw packet with some logging if exception
ssize_t receive_packet(int sockfd, void *buffer, size_t buffer_len,
                       struct sockaddr_in &dest_addr);
//---------------------------------------------------------------------|
// Close socket
void close_socket(int socket_fd);
/*--------------------------------------------------------------------*/
}; // namespace Network
