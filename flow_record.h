#ifndef FLOW_RECORD_H
#define FLOW_RECORD_H

#include "utils.h"

class FlowRecord {
public:
    FlowRecord(const Packet& packet);
    void update(const Packet& packet);
    bool isActive(time_t current_time, int active_timeout, int inactive_timeout) const;

    const std::string& getSrcIP() const;
    const std::string& getDstIP() const;
    uint16_t getSrcPort() const;
    uint16_t getDstPort() const;
    uint8_t getProtocol() const;
    uint32_t getPacketCount() const;
    uint32_t getByteCount() const;
    time_t getFirstSeen() const;
    time_t getLastSeen() const;
    uint8_t getTCPFlags() const;

private:
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint32_t packet_count;
    uint32_t byte_count;
    time_t first_seen;
    time_t last_seen;
    uint8_t tcp_flags;
};

#endif // FLOW_RECORD_H
