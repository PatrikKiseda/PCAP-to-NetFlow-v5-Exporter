#include "packet_reader.h"
#include "flow_manager.h"
#include "netflow_exporter.h"

// main function used to execute the netflow probe
int main(int argc, char* argv[]) {

    // argument variables
    std::string collector_host;
    uint16_t collector_port;
    std::string pcap_file;     // pcap file path
    int active_timeout = 60;   //default timeout == 60
    int inactive_timeout = 60;

    // command line args parsing
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        // splitting one argument string into 2 values
        if (arg.find(":") != std::string::npos) {
            size_t colon_pos = arg.find(":");
            collector_host = arg.substr(0, colon_pos);
            collector_port = std::stoi(arg.substr(colon_pos + 1));
        }

        else if (arg.find(".pcap") != std::string::npos) {
            pcap_file = arg;
        }

        else if (arg == "-a" && i + 1 < argc) {
            active_timeout = std::stoi(argv[++i]);
        }
        else if (arg == "-i" && i + 1 < argc) {
            inactive_timeout = std::stoi(argv[++i]);
        }
        else {
            std::cerr << "Invalid argument: " << arg << std::endl;
            return EXIT_FAILURE;
        }
    }
    /*DEBUG     checking if the arguments are parsed correctly
    std::cout << "Collector Host   : " << collector_host << std::endl;
    std::cout << "Collector Port   : " << collector_port << std::endl;
    std::cout << "PCAP File        : " << pcap_file << std::endl;
    std::cout << "Active Timeout   : " << active_timeout << " seconds" << std::endl;
    std::cout << "Inactive Timeout : " << inactive_timeout << " seconds" << std::endl;
    */

    // in case of wrong pcap file or wrong collector specification
    if (collector_host.empty() || pcap_file.empty()) {
        std::cerr << "Usage: ./p2nprobe <host>:<port> <pcap_file> [-a <active_timeout> -i <inactive_timeout>]" << std::endl;
        return EXIT_FAILURE;
    }
    
    //  initialization of key components 
    PacketReader packetReader(pcap_file);  // used to read packets from the PCAP file
    FlowManager flowManager(active_timeout, inactive_timeout);  // manage flows
    NetFlowExporter netflowExporter(collector_host, collector_port);  // export flows

    struct pcap_pkthdr* header;  // header information for each packet
    const u_char* data;          // packet data
    int packet_count = 0;        // count of already processed packets

    // loop used to read and process packets
    while (true) {
        int res = packetReader.getNextPacket(&header, &data);
        if (res == 1) { //packet read sucessfully
            packet_count++;
            /*DEBUG
            std::cout << "\n\n";
            std::cout << "Packet          #" << packet_count << std::endl;
            std::cout << "Timestamp       : " << header->ts.tv_sec << "." << header->ts.tv_usec << std::endl;
            std::cout << "Captured Length : " << header->caplen << std::endl;
            std::cout << "Original Length : " << header->len << std::endl;
            */        

            // checking the correctness of the header length against a library value
            if (header->caplen < sizeof(struct ether_header)) {
                std::cerr << "Packet too short for Ethernet header." << std::endl;
                continue;
            }

            // TCP and IP header info assignment
            const u_char* ip_packet = data + sizeof(struct ether_header);
            int ip_header_length;

            struct iphdr* ip_header = (struct iphdr*)ip_packet;
            ip_header_length = ip_header->ihl * 4;

            // processing only tcp packets
            if (ip_header->protocol != IPPROTO_TCP) {
                continue;
            }

            // ip extraction
            struct in_addr src_ip, dst_ip;
            src_ip.s_addr = ip_header->saddr;
            dst_ip.s_addr = ip_header->daddr;

            
            char src_ip_str[INET_ADDRSTRLEN];
            char dst_ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &src_ip, src_ip_str, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &dst_ip, dst_ip_str, INET_ADDRSTRLEN);

            // getting the tcp header
            const u_char* tcp_packet = ip_packet + ip_header_length;
            struct tcphdr* tcp_header = (struct tcphdr*)tcp_packet;

       
            uint16_t src_port = ntohs(tcp_header->source);
            uint16_t dst_port = ntohs(tcp_header->dest);

            Packet packet;
            packet.src_ip = src_ip_str;
            packet.dst_ip = dst_ip_str;
            packet.src_port = src_port;
            packet.dst_port = dst_port;
            packet.protocol = IPPROTO_TCP;
            packet.length = header->len;
            packet.timestamp = header->ts;  
            packet.tcp_flags = tcp_header->th_flags;

            /*DEBUG
            std::cout << "Packet Details :" << std::endl;
            std::cout << "Src IP         : " << packet.src_ip << std::endl;
            std::cout << "Dst IP         : " << packet.dst_ip << std::endl;
            std::cout << "Src Port       : " << packet.src_port << std::endl;
            std::cout << "Dst Port       : " << packet.dst_port << std::endl;
            std::cout << "Protocol       : " << static_cast<int>(packet.protocol) << std::endl;
            std::cout << "Length         : " << packet.length << std::endl;
            std::cout << "Timestamp      : " << packet.timestamp << std::endl;
            std::cout << "TCP Flags      : " << static_cast<int>(packet.tcp_flags) << std::endl;
            */

            flowManager.addPacket(packet);

            struct timeval current_time = packet.timestamp;
            auto flows_to_export = flowManager.checkTimeouts(current_time);

            // export flows in the export queue
            if (!flows_to_export.empty()) {
                netflowExporter.exportFlows(flows_to_export);
            }

            } else if (res == 0) { // EOF
        
                break;
            } else {
                break;
            }
        }

    // DENUG std::cout << "Total packets processed: " << packet_count << std::endl;

    // export remaining flows after processing everything else
    auto remaining_flows = flowManager.exportAllFlows();
    if (!remaining_flows.empty()) {
        netflowExporter.exportFlows(remaining_flows);
    }

    return 0;

}
