// network
#pragma once
#include <arpa/inet.h>
#include <chrono> // for timeouts
#include <cstdint>
#include <netinet/in.h>
#include <netinet/ip.h>  // For iphdr
#include <netinet/tcp.h> // For tcphdr
#include <string.h>
#include <string>
#include <sys/types.h> // For socket types
#include <vector>

namespace Network {
#define DATAGRAM_SIZE 1460
#define OPT_SIZE 32

/*------------------- PACKET TYPES CONSTRUCTION -----------------------*/
// Create connection request packet
void create_syn_packet(struct sockaddr_in *src, struct sockaddr_in *dst,
                       unsigned char **packet, int *packet_size);
//----------------------------------------------------------------------|
// Create ACK packet
void create_ack_packet(struct sockaddr_in *src, struct sockaddr_in *dst,
                       int32_t seq, int32_t ack_seq, unsigned char **packet,
                       int *packet_size);
//----------------------------------------------------------------------|
// Create data packet
void create_data_packet(struct sockaddr_in *src, struct sockaddr_in *dst,
                        int32_t seq, int32_t ack_seq, const std::string &data,
                        unsigned char **packet, int *packet_size);
/*--------------------------------------------------------------------*/

/*----------------  BASIC COMMUNICATEES INITIALIZATION  --------------*/
// Create socket with some logging on exception
int create_socket(int domain, int type, int protocol);
//---------------------------------------------------------------------|
// Initialize server socket
bool create_server_socket(int &server_sockfd, struct sockaddr_in &server_addr,
                          const char *ip, int port);
//---------------------------------------------------------------------|
// Initialize client socket
int create_client_socket(int &client_sockfd);
//---------------------------------------------------------------------|
// Bind server's socket
bool bind_to_port(int port, int &server_sockfd,
                  struct sockaddr_in &server_addr);
/*--------------------------------------------------------------------*/

/*--------------------  COMMUNICATION INTERFACE ----------------------*/
// Read ip, tcp headers, checksum etc.
void parse_packet(unsigned char *packet, struct sockaddr_in &client_addr,
                  uint32_t *seq, uint32_t *ack);
//----------------------------------------------------------------------|
// Calculate checksum of packet
unsigned short checksum(void *buffer, unsigned len);
//----------------------------------------------------------------------|
// Listen for incoming connections
bool listen_client(int &server_sockfd, int numcl,
                   struct sockaddr_in &server_addr,
                   struct sockaddr_in &client_addr);
//---------------------------------------------------------------------|
// Make connection request
// Send SYN signal and listen for SYN ACK
bool connect_to_server(int &client_sockfd, struct sockaddr_in &client_addr,
                       struct sockaddr_in &server_addr, const char *ip,
                       int port);
//---------------------------------------------------------------------|
// Accept pending connection request
// Respond to SYN with SYN ACK
int accept_connection(int &server_sockfd, struct sockaddr_in server_addr,
                      struct sockaddr_in client_addr);
//---------------------------------------------------------------------|
// Send raw packet with some logging if exception
ssize_t send_packet(int sockfd, void *packet, size_t packet_len,
                    struct sockaddr_in *dest_addr);
//---------------------------------------------------------------------|
// Receive raw packet with some logging if exception
ssize_t receive_packet(int sockfd, void *buffer, size_t buffer_len);
//---------------------------------------------------------------------|
// Close socket
void close_socket(int socket_fd);
/*--------------------------------------------------------------------*/
}; // namespace Network
