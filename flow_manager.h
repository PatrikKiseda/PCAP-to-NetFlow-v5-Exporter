#ifndef FLOW_MANAGER_H
#define FLOW_MANAGER_H

#include "utils.h"
#include "flow_record.h"

class FlowManager {
public:
    FlowManager(int active_timeout, int inactive_timeout);
    void addPacket(const Packet& packet);
    std::vector<FlowRecord> checkTimeouts(time_t current_time);
    std::vector<FlowRecord> exportAllFlows();

private:
    std::string generateFlowKey(const Packet& packet);
    std::unordered_map<std::string, FlowRecord> active_flows;
    int active_timeout;
    int inactive_timeout;
};

#endif // FLOW_MANAGER_H
