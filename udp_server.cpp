/*
  udp_server.cpp
 
  Description:
  Simple UDP program that listens on port 2055.
  Receives UDP packets, prints the size of each one of them.
  
  Usage:
    Compile using:
        g++ -o udp_server udp_server.cpp
    
    Run using:
        ./udp_server
    Stop:
        Ctrl+c
  
  Notes:
  - checks if there is any traffic at all 
 */

#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

int main() {
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);
    char buffer[1024];

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Server: Error creating socket");
        return 1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(2055);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Server: Error binding socket");
        return 1;
    }

    std::cout << "Server listening on port 2055..." << std::endl;

    while (true) {
        ssize_t recv_len = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&client_addr, &addr_len);
        if (recv_len < 0) {
            perror("Server: Error receiving data");
            continue;
        }
        std::cout << "Received " << recv_len << " bytes from client." << std::endl;
    }

    close(sockfd);
    return 0;
}
