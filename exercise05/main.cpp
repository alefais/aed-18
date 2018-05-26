//
// Created by Alessandra Fais
// AED course - MCSN - University of Pisa
// A.A. 2017/18
//

#include <iostream>
#include <exception>
#include <pcap.h>

#include "pcap_flow.h"

int main(int argc, char* argv[]) {

    if (argc < 4) {
        std::cerr << "Usage: "
                  << argv[0]
                  << " [-i <interface>] | [-f <file_name>] <num_pkt>"
                  << std::endl;
        return 1;
    }

    int num_pkt = std::atoi(argv[3]);
    char err_buf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = nullptr;
    switch (argv[1][1]) {
        case 'n':
            handle = pcap_open_live(argv[2], 100, 1, 1000, err_buf);
            break;
        case 'f':
            handle = pcap_open_offline(argv[2], err_buf);
            break;
        default:
            break;
    }

    try {
        Pcap_flow dump(handle);
        dump.sniff(num_pkt);
        dump.list();
    } catch (const std::invalid_argument& e) {
        std::cout << "Invalid argument exception: " << e.what() << "\n";
        return 1;
    }

    return 0;
}