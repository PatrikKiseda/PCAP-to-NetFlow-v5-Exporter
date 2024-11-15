#include "flow_record.h"

FlowRecord::FlowRecord(const Packet& packet)
    : src_ip(packet.src_ip), dst_ip(packet.dst_ip),
      src_port(packet.src_port), dst_port(packet.dst_port),
      protocol(packet.protocol), packet_count(1),
      byte_count(packet.length), first_seen(packet.timestamp),
      last_seen(packet.timestamp), tcp_flags(packet.tcp_flags) {}

const std::string& FlowRecord::getSrcIP() const {
    return src_ip;
}

const std::string& FlowRecord::getDstIP() const {
    return dst_ip;
}

void FlowRecord::update(const Packet& packet) {
    packet_count++;
    byte_count += packet.length;
    last_seen = packet.timestamp;
    tcp_flags |= packet.tcp_flags;
}

bool FlowRecord::isActive(time_t current_time, int active_timeout, int inactive_timeout) const {
    if ((current_time - first_seen) >= active_timeout) {
        return false; 
    }
    if ((current_time - last_seen) >= inactive_timeout) {
        return false; 
    }
    return true;
}


