#include "packet_reader.h"

PacketReader::PacketReader(const std::string& pcap_file) {
    pcap_handle = pcap_open_offline(pcap_file.c_str(), errbuf);
    if (!pcap_handle) {
        std::cerr << "Error opening PCAP file: " << errbuf << std::endl;
        exit(EXIT_FAILURE);
    }
}

PacketReader::~PacketReader() {
    if (pcap_handle) {
        pcap_close(pcap_handle);
    }
}

int PacketReader::getNextPacket(struct pcap_pkthdr** header, const u_char** packet_data) {
    int result = pcap_next_ex(pcap_handle, header, packet_data);
    if (result == PCAP_ERROR) {
        std::cerr << "Error reading the packet: " << pcap_geterr(pcap_handle) << std::endl;
    }
    return result;
}
