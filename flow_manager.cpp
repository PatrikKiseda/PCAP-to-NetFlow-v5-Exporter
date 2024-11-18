#include "flow_manager.h"

// constructor
FlowManager::FlowManager(int active_timeout, int inactive_timeout)
    : active_timeout(active_timeout), inactive_timeout(inactive_timeout) {}

// new flow or adding a packet to an already existing flow
void FlowManager::addPacket(const Packet& packet) {
    // keygen
    std::string flow_key = generateFlowKey(packet);
    auto it = active_flows.find(flow_key);
    if (it != active_flows.end()) {
        // flow exists
        //DEBUG std::cout << "\nUpdating existing flow: " << flow_key << "\n";
        it->second.update(packet);
    } else {
        //flow doesnt exist
        //DEBUG std::cout << "\n\n<<New flow>>\n\n";
        FlowRecord new_flow(packet);
        active_flows.insert({flow_key, new_flow});
    }
}

//checks timeouts
std::vector<FlowRecord> FlowManager::checkTimeouts(const struct timeval& current_time) {
    std::vector<FlowRecord> flows_to_export;

    // going through active flows looking for timed-out flows
    for (auto it = active_flows.begin(); it != active_flows.end();) {
        if (!it->second.isActive(current_time, active_timeout, inactive_timeout)) {
            // flow timed out, export it
            flows_to_export.push_back(it->second);
            it = active_flows.erase(it);
        } else {
            // next
            ++it;
        }
    }
    return flows_to_export;
}

// export all when program is ending
std::vector<FlowRecord> FlowManager::exportAllFlows() {
    std::vector<FlowRecord> all_flows;
    // collecting flows
    for (const auto& pair : active_flows) {
        all_flows.push_back(pair.second);
    }
    active_flows.clear();
    return all_flows;
}

// keygen function -> key made from the unique characteristic of the flow 
std::string FlowManager::generateFlowKey(const Packet& packet) {
    return packet.src_ip + ":" + std::to_string(packet.src_port) + "->" +
           packet.dst_ip + ":" + std::to_string(packet.dst_port) + ":" +
           std::to_string(packet.protocol);
}
