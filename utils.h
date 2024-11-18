#ifndef UTILS_H
#define UTILS_H

// Stdlibs and networking headers
#include <unistd.h>          // Constants and types
#include <string>            // C++ string 
#include <cstdint>           // integers
#include <iostream>          // Inputs outputs 
#include <cstdlib>           // utils
#include <pcap.h>            // PCAP library
#include <netinet/ip.h>      // IP header structures
#include <netinet/tcp.h>     // TCP header structures
#include <netinet/udp.h>     // UDP header structures
#include <netinet/if_ether.h>// ethernet header structures
#include <arpa/inet.h>       // internet adress lib
#include <unordered_map>     // unordered map (hash table) container
#include <vector>            // C++ array
#include <chrono>            // time utils
#include <cstring>           
#include <sys/socket.h>      // sockets
#include <netdb.h>           // network database for addresses

struct Packet {
    std::string src_ip;       // source ip
    std::string dst_ip;       // dst ip
    uint16_t src_port;  
    uint16_t dst_port;
    uint8_t protocol;
    uint32_t length;               // total length
    struct timeval timestamp;      // timestamp of capture
    uint8_t tcp_flags;             // tcpflags
};


#endif