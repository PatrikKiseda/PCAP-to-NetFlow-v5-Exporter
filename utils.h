#ifndef UTILS_H
#define UTILS_H

#include <string>      
#include <cstdint>      
#include <iostream>     
#include <cstdlib> 
#include <pcap.h>  
#include <netinet/ip.h>   
#include <netinet/tcp.h>  
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>   

struct Packet {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint32_t length;
    time_t timestamp;
    uint8_t tcp_flags;
};

#endif
