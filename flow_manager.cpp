#include "flow_manager.h"

FlowManager::FlowManager(int active_timeout, int inactive_timeout)
    : active_timeout(active_timeout), inactive_timeout(inactive_timeout) {}

void FlowManager::addPacket(const Packet& packet) {
    std::string flow_key = generateFlowKey(packet);
    auto it = active_flows.find(flow_key);
    if (it != active_flows.end()) {
        it->second.update(packet);
    } else {
        FlowRecord new_flow(packet);
        active_flows.insert({flow_key, new_flow});
    }
}

std::vector<FlowRecord> FlowManager::checkTimeouts(time_t current_time) {
    std::vector<FlowRecord> flows_to_export;
    for (auto it = active_flows.begin(); it != active_flows.end();) {
        if (!it->second.isActive(current_time, active_timeout, inactive_timeout)) {
            flows_to_export.push_back(it->second);
            it = active_flows.erase(it);
        } else {
            ++it;
        }
    }
    return flows_to_export;
}

std::vector<FlowRecord> FlowManager::exportAllFlows() {
    std::vector<FlowRecord> all_flows;
    for (const auto& pair : active_flows) {
        all_flows.push_back(pair.second);
    }
    active_flows.clear();
    return all_flows;
}

std::string FlowManager::generateFlowKey(const Packet& packet) {
    return packet.src_ip + ":" + std::to_string(packet.src_port) + "->" +
           packet.dst_ip + ":" + std::to_string(packet.dst_port) + ":" +
           std::to_string(packet.protocol);
}
