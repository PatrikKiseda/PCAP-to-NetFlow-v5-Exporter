#ifndef UTILS_H
#define UTILS_H
#endif

int main(int argc, char* argv[]) {
    std::string collector_host;
    uint16_t collector_port;
    std::string pcap_file;
    int active_timeout = 60;
    int inactive_timeout = 60;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

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

    if (collector_host.empty() || pcap_file.empty()) {
        std::cerr << "Usage: ./p2nprobe <host>:<port> <pcap_file> [-a <active_timeout> -i <inactive_timeout>]" << std::endl;
        return EXIT_FAILURE;
    }

}
