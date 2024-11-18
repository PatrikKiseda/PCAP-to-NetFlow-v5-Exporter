#ifndef NETFLOW_EXPORTER_H
#define NETFLOW_EXPORTER_H

#include "utils.h"
#include "flow_record.h"

class NetFlowExporter {
public:
    NetFlowExporter(const std::string& collector_host, uint16_t collector_port);
    ~NetFlowExporter();
    void exportFlows(const std::vector<FlowRecord>& flows);

private:
    void buildHeader(uint16_t count, uint32_t sys_uptime, uint32_t unix_secs, uint32_t unix_nsecs, uint32_t flow_sequence);
    void buildFlowRecord(const FlowRecord& flow);
    void sendPacket();
    int sockfd;
    struct sockaddr_in collector_addr;
    uint32_t flow_sequence;
    std::chrono::steady_clock::time_point start_time; // for SysUptime
    struct timeval system_boot_time;
    uint32_t sys_uptime_base; 
    uint32_t sys_uptime;      


    static const size_t MAX_PACKET_SIZE = 24 + (30 * 48); // Header + 30 flow records
    uint8_t packet_buffer[MAX_PACKET_SIZE];
    size_t packet_size; 
    uint16_t flow_count; 
};

#endif // NETFLOW_EXPORTER_H