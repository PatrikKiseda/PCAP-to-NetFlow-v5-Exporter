#ifndef PACKET_READER_H
#define PACKET_READER_H

#include "utils.h"

class PacketReader {
public:
    PacketReader(const std::string& pcap_file);
    ~PacketReader();
    int getNextPacket(struct pcap_pkthdr** header, const u_char** packet_data);

private:
    pcap_t* pcap_handle;
    char errbuf[PCAP_ERRBUF_SIZE];
};

#endif // PACKET_READER_H
