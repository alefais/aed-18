//
// Created by Alessandra Fais
// AED course - MCSN - University of Pisa
// A.A. 2017/18
//

#include <iostream>
#include <pcap.h>

#include "utils.h"

int main(int argc, char* argv[]) {

    pcap_t* handle;
    char err_buf[PCAP_ERRBUF_SIZE];

    if (argc < 3) {
        std::cerr << "Usage: "
                  << argv[0]
                  << " <pcap file> <num_pkt>"
                  << std::endl;
        return 1;
    }

    // Open a pcap descriptor
    handle = pcap_open_offline(argv[1], err_buf);
    if (handle == nullptr) {
        std::cerr << "pcap handle is null: "
                  << err_buf
                  << std::endl;
        return 1;
    }

    int num_pkt = std::atoi(argv[2]);

    // Read packets
    if (pcap_loop(handle, num_pkt, pkt_handler_callback, nullptr) == -1) {
        std::cerr << "pcap loop failed" << std::endl;
        return 1;
    }

    pcap_close(handle);

    return 0;
}