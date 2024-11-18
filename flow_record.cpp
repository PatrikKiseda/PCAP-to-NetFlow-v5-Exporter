#include "flow_record.h"

// constructor
FlowRecord::FlowRecord(const Packet& packet)
    : src_ip(packet.src_ip), dst_ip(packet.dst_ip),
      src_port(packet.src_port), dst_port(packet.dst_port),
      protocol(packet.protocol), packet_count(1),        
      byte_count(packet.length), tcp_flags(packet.tcp_flags){
        first_seen = packet.timestamp;
        last_seen = packet.timestamp;
      }

// getter for source IP address
const std::string& FlowRecord::getSrcIP() const {
    return src_ip;
}

// getter for destination
const std::string& FlowRecord::getDstIP() const {
    return dst_ip;
}

// source port
uint16_t FlowRecord::getSrcPort() const {
    return src_port;
}

// destination port
uint16_t FlowRecord::getDstPort() const {
    return dst_port;
}

//protocol type
uint8_t FlowRecord::getProtocol() const {
    return protocol;
}

// packets
uint32_t FlowRecord::getPacketCount() const {
    return packet_count;
}

// bytes
uint32_t FlowRecord::getByteCount() const {
    return byte_count;
}

// timestamp for the first packet in the flow
const struct timeval& FlowRecord::getFirstSeen() const {
    return first_seen;
}

// timestamp for the last packet in the flow
const struct timeval& FlowRecord::getLastSeen() const {
    return last_seen;
}

uint8_t FlowRecord::getTCPFlags() const {
    return tcp_flags;
}

// updates flow with new packet info
void FlowRecord::update(const Packet& packet) {
    packet_count++;
    byte_count += packet.length;
    last_seen = packet.timestamp;
    tcp_flags |= packet.tcp_flags; //bitwise or to update tcp flags
}

// helper function, returns time difference
static double time_diff(const struct timeval& end, const struct timeval& start) {
    return (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1e6;
}

// is Active and inactive check
bool FlowRecord::isActive(const struct timeval& current_time, int active_timeout, int inactive_timeout) const {
    double time_since_first = time_diff(current_time, first_seen);
    if (time_since_first >= active_timeout) {
        return false;  //expired 
    }
    double time_since_last = time_diff(current_time, last_seen);
    if (time_since_last >= inactive_timeout) {
        return false; //expired 
    }
    return true;// active 
}