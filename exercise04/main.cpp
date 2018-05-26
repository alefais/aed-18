//
// Created by Alessandra Fais
// AED course - MCSN - University of Pisa
// A.A. 2017/18
//

#include <iostream>
#include <exception>
#include <pcap.h>

#include "pcap_ipset.h"

int main(int argc, char* argv[]) {

    if (argc < 3) {
        std::cerr << "Usage: "
                  << argv[0]
                  << " <pcap file> <num_pkt>"
                  << std::endl;
        return 1;
    }

    int num_pkt = std::atoi(argv[2]);
    char err_buf[PCAP_ERRBUF_SIZE];

    try {
        Pcap_IPset dump(pcap_open_offline(argv[1], err_buf));
        dump.sniff(num_pkt);
        dump.list();
    } catch (const std::invalid_argument& e) {
        std::cout << "Invalid argument exception: " << e.what() << "\n";
        return 1;
    }

    return 0;
}