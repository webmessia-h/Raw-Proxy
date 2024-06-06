// network
#pragma once
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>  // For iphdr
#include <netinet/tcp.h> // For tcphdr
#include <string.h>
#include <string>
#include <sys/types.h> // For socket types
#include <vector>
/* Cryptography libs*/
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

//
namespace Network {
#define OPT_SIZE 24
// Calculate checksum of packet
unsigned short checksum(void *buffer, unsigned len);

// TODO: ideally implement:

/*------------------- PACKET TYPES CONSTRUCTION -----------------------*/
// Create connection request packet
void create_syn_packet(struct sockaddr_in *src, struct sockaddr_in *dst,
                       unsigned char **packet, int *packet_size);
//|---------------------------------------------------------------------|
// Create ACK packet
void create_ack_packet(struct sockaddr_in *src, struct sockaddr_in *dst,
                       int32_t seq, int32_t ack_seq, unsigned char **packet,
                       int *packet_size);
//|---------------------------------------------------------------------|
// Read sequence
void read_seq_and_ack(const char *packet, uint32_t *seq, uint32_t *ack);
//|---------------------------------------------------------------------|
// Create data packet
void create_data_packet(struct sockaddr_in *src, struct sockaddr_in *dst,
                        const std::string &data, unsigned char **packet,
                        int *packet_size);
/*--------------------------------------------------------------------*/

/*----------------  BASIC COMMUNICATEES INITIALIZATION  --------------*/
// Create socket with some logging on exception
int create_socket(int domain, int type, int protocol);
//|--------------------------------------------------------------------|
// Initialize server socket
bool create_server_socket(int &server_sockfd, struct sockaddr_in &server_addr,
                          const char *ip, int port);
//|--------------------------------------------------------------------|
// Initialize client socket
int create_client_socket(int &client_sockfd);
//|--------------------------------------------------------------------|
// Bind server's socket
bool bind_to_port(int port, int &server_sockfd,
                  struct sockaddr_in &server_addr);
/*--------------------------------------------------------------------*/

/*--------------------  COMMUNICATION INTERFACE ----------------------*/
// Listen for incoming connections
// TODO: change to receive in a loop maybe use another thread and on receival
// notify other thread to send to server and sleep until done
bool listen_client(int &server_sockfd, int numcl);
//|--------------------------------------------------------------------|
// Make connection request
// TODO: ideally send SYN signal and listen for SYN ACK
bool connect_to_server(int &client_sockfd, struct sockaddr_in &server_addr,
                       const char *ip, int port);
//|--------------------------------------------------------------------|
// Accept pending connection request
// TODO:: ideally respond to SYN with SYN ACK
int accept_connection(int &server_sockfd, int &communication_sockfd);
//|--------------------------------------------------------------------|
// Check connection via handshake
// TODO: encapsulate all above :)
void handshake(int &socket_fd, sockaddr_in *dest_addr);
//|--------------------------------------------------------------------|
// Send raw packet with some logging if exception
ssize_t send_raw_packet(int sockfd, void *packet, size_t packet_len,
                        struct sockaddr_in *dest_addr);
//|--------------------------------------------------------------------|
// Receive raw packet with some logging if exception
ssize_t receive_raw_packet(int sockfd, void *buffer, size_t buffer_len);
//|--------------------------------------------------------------------|
// Close socket
void close_socket(int socket_fd);
/*--------------------------------------------------------------------*/
}; // namespace Network
