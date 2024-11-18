#include "netflow_exporter.h"

static uint32_t time_diff_ms(const struct timeval& end, const struct timeval& start) {
    return (end.tv_sec - start.tv_sec) * 1000 + (end.tv_usec - start.tv_usec) / 1000;
}

// constructor
NetFlowExporter::NetFlowExporter(const std::string& collector_host, uint16_t collector_port)
    : flow_sequence(0), packet_size(0), flow_count(0), sys_uptime_base(0), sys_uptime(0) {
    //DEBUG std::cout <<"\nRESOLVING\n";
    // initialization of UDP socket for export
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    memset(&collector_addr, 0, sizeof(collector_addr));
    collector_addr.sin_family = AF_INET;
    collector_addr.sin_port = htons(collector_port);

    // resolving collector address
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; 
    hints.ai_socktype = SOCK_DGRAM;

    std::string port_str = std::to_string(collector_port);

    int err = getaddrinfo(collector_host.c_str(), port_str.c_str(), &hints, &res);
    if (err != 0) {
        std::cerr << "Error resolving collector address: " << gai_strerror(err) << std::endl;
        exit(EXIT_FAILURE);
    }

    memcpy(&collector_addr, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
        // initialize start time
        start_time = std::chrono::steady_clock::now();
    }

NetFlowExporter::~NetFlowExporter() {
    if (sockfd >= 0) {
        close(sockfd);
    }
}

void NetFlowExporter::exportFlows(const std::vector<FlowRecord>& flows) {
    for (const auto& flow : flows) {
        buildFlowRecord(flow);
        flow_count++;

        // if packet is full, send it
        if (flow_count == 30) {
            sendPacket();
            flow_count = 0;
            packet_size = 0;
        }
    }

    // send out the remaining data
    if (flow_count > 0) {
        sendPacket();
        flow_count = 0;
        packet_size = 0;
    }
}

// building packet header part by part in this method
void NetFlowExporter::buildHeader(uint16_t count, uint32_t sys_uptime, uint32_t unix_secs, uint32_t unix_nsecs, uint32_t flow_sequence) {
    uint8_t* ptr = packet_buffer;

    // Version
    uint16_t version = htons(5);
    memcpy(ptr, &version, 2);
    ptr += 2;

    // Count
    uint16_t count_net = htons(count);
    memcpy(ptr, &count_net, 2);
    ptr += 2;

    // SysUptime
    uint32_t sys_uptime_net = htonl(sys_uptime);
    memcpy(ptr, &sys_uptime_net, 4);
    ptr += 4;

    // Unix seconds
    uint32_t unix_secs_net = htonl(unix_secs);
    memcpy(ptr, &unix_secs_net, 4);
    ptr += 4;

    // Unix nanoseconds
    uint32_t unix_nsecs_net = htonl(unix_nsecs);
    memcpy(ptr, &unix_nsecs_net, 4);
    ptr += 4;

    // Flow sequence
    uint32_t flow_sequence_net = htonl(flow_sequence);
    memcpy(ptr, &flow_sequence_net, 4);
    ptr += 4;

    // Engine Type and ID
    *ptr++ = 0; // Engine Type
    *ptr++ = 0; // Engine ID

    // Sampling Interval
    uint16_t sampling_interval = 0;
    memcpy(ptr, &sampling_interval, 2);
    ptr += 2;

    // packet_size update
    packet_size = ptr - packet_buffer;
}

// building records here 
void NetFlowExporter::buildFlowRecord(const FlowRecord& flow) {
    //DEBUG std::cout <<"\nBUILDING\n";
    uint32_t sys_uptime;

    auto now = std::chrono::steady_clock::now();
    
    if (sys_uptime_base == 0) {
        sys_uptime_base = flow.getFirstSeen().tv_sec * 1000 + flow.getFirstSeen().tv_usec / 1000;
    }

    sys_uptime = (flow.getLastSeen().tv_sec * 1000 + flow.getLastSeen().tv_usec / 1000) - sys_uptime_base;

    // if no header yet, build it
    if (packet_size == 0) {
        uint32_t unix_secs = flow.getLastSeen().tv_sec;
        uint32_t unix_nsecs = flow.getLastSeen().tv_usec * 1000;
        buildHeader(0, sys_uptime, unix_secs, unix_nsecs, flow_sequence);
    }

    uint8_t* ptr = packet_buffer + packet_size;

    // srcaddr
    struct in_addr src_addr;
    inet_pton(AF_INET, flow.getSrcIP().c_str(), &src_addr);
    memcpy(ptr, &src_addr, 4);
    ptr += 4;

    // dstaddr
    struct in_addr dst_addr;
    inet_pton(AF_INET, flow.getDstIP().c_str(), &dst_addr);
    memcpy(ptr, &dst_addr, 4);
    ptr += 4;

    // nexthop (set to zero)
    uint32_t nexthop = 0;
    memcpy(ptr, &nexthop, 4);
    ptr += 4;

    // input (set to zero)
    uint16_t input = 0;
    memcpy(ptr, &input, 2);
    ptr += 2;

    // output (set to zero)
    uint16_t output = 0;
    memcpy(ptr, &output, 2);
    ptr += 2;

    // dPkts
    uint32_t dPkts = htonl(flow.getPacketCount());
    memcpy(ptr, &dPkts, 4);
    ptr += 4;

    // dOctets
    uint32_t dOctets = htonl(flow.getByteCount());
    memcpy(ptr, &dOctets, 4);
    ptr += 4;

    // first and last relative to sys_uptime_base variable
    uint32_t flow_first_ms = (flow.getFirstSeen().tv_sec * 1000 + flow.getFirstSeen().tv_usec / 1000) - sys_uptime_base;
    uint32_t flow_last_ms = (flow.getLastSeen().tv_sec * 1000 + flow.getLastSeen().tv_usec / 1000) - sys_uptime_base;

    // check if first and last are within sys_uptime before setting them
    if (flow_first_ms > sys_uptime) flow_first_ms = sys_uptime;
    if (flow_last_ms > sys_uptime) flow_last_ms = sys_uptime;

    // converting byte order and copying the value to packet buffer
    uint32_t first_net = htonl(flow_first_ms);
    memcpy(ptr, &first_net, 4);
    ptr += 4;

    uint32_t last_net = htonl(flow_last_ms);
    memcpy(ptr, &last_net, 4);
    ptr += 4;
    
    // srcport
    uint16_t srcport = htons(flow.getSrcPort());
    memcpy(ptr, &srcport, 2);
    ptr += 2;

    // dstport
    uint16_t dstport = htons(flow.getDstPort());
    memcpy(ptr, &dstport, 2);
    ptr += 2;

    // pad1 (set to zero)
    *ptr++ = 0;

    // tcp_flags
    *ptr++ = flow.getTCPFlags();

    // prot
    *ptr++ = flow.getProtocol();

    // tos (set to zero)
    *ptr++ = 0;

    // src_as (set to zero)
    uint16_t src_as = 0;
    memcpy(ptr, &src_as, 2);
    ptr += 2;

    // dst_as (set to zero)
    uint16_t dst_as = 0;
    memcpy(ptr, &dst_as, 2);
    ptr += 2;

    // src_mask (set to zero)
    *ptr++ = 0;

    // dst_mask (set to zero)
    *ptr++ = 0;

    // pad2 (set to zero)
    uint16_t pad2 = 0;
    memcpy(ptr, &pad2, 2);
    ptr += 2;

    // update packet_size again
    packet_size = ptr - packet_buffer;
}


void NetFlowExporter::sendPacket() {
    // update the flow count in the header
    uint16_t count_net = htons(flow_count);
    memcpy(packet_buffer + 2, &count_net, 2);
    //DEBUGstd::cout << "\nSENDING PACKET :\nto sockfd:"<< sockfd << "\nsize:"<<packet_size<< "\n\n";
    // sending the packet
    ssize_t sent_bytes = sendto(sockfd, packet_buffer, packet_size, 0, (struct sockaddr*)&collector_addr, sizeof(collector_addr));
    if (sent_bytes < 0) {
        perror("Error sending NetFlow packet");
    } else {
        //DEBUG std::cout << "\nSent NetFlow packet with " << flow_count << " flow records. Bytes sent: " << sent_bytes << std::endl;
    }

    flow_sequence += flow_count;

    // reset packet_size and flow_count for next use
    packet_size = 0;
    flow_count = 0;
}
