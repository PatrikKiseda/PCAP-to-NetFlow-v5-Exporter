#include "packet_reader.h"

// constructor, initializes PacketReader with the PCAP file 
PacketReader::PacketReader(const std::string& pcap_file) {
    // open PCAP
    pcap_handle = pcap_open_offline(pcap_file.c_str(), errbuf);
    if (!pcap_handle) {
        // error
        std::cerr << "Error opening PCAP file: " << errbuf << std::endl;
        exit(EXIT_FAILURE);
    }
}

// destructor
PacketReader::~PacketReader() {
    if (pcap_handle) {
        pcap_close(pcap_handle); // close the PCAP file 
    }
}

// reads the next packet
int PacketReader::getNextPacket(struct pcap_pkthdr** header, const u_char** packet_data) {
    // using pcap_next_ex function here
    int result = pcap_next_ex(pcap_handle, header, packet_data);
    // error
    if (result == PCAP_ERROR) {
        std::cerr << "Error reading the packet: " << pcap_geterr(pcap_handle) << std::endl;
    }
    return result;
}
