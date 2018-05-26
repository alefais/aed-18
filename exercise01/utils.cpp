//
// Created by Alessandra Fais
// AED course - MCSN - University of Pisa
// A.A. 2017/18
//

#include <iostream>
#include <cstring>
#include <pcap.h>
#include <iomanip>
#include "utils.h"

/*
 * Print the list of network devices.
 */
void print_devs() {
    pcap_if_t* devs;
    char err_buf1[PCAP_ERRBUF_SIZE];

    pcap_findalldevs(&devs, err_buf1);
    std::cout << "List of network devices:" << std::endl;

    pcap_if_t* iter = devs;
    while (iter != nullptr) {
        std::cout << std::setw(6) << std::left << "name: "
                  << std::setw(10) << std::left << iter->name
                  << std::setw(10) << std::left << " descr: "
                  << std::setw(10) << std::left << (((iter->description) != nullptr) ? iter->description : "NO DESCRIPTION")
                  << std::endl;
        iter = iter->next;
    }
}

/*
 * Check if the network device dev is one of currently available network devices.
 */
bool find_dev(char* dev) {
    pcap_if_t* devs;
    char err_buf1[PCAP_ERRBUF_SIZE];
    bool found_if = false;

    pcap_findalldevs(&devs, err_buf1);

    pcap_if_t* iter = devs;
    while (!found_if && iter != nullptr) {
        if (strcmp(dev, iter->name) == 0) found_if = true;
        iter = iter->next;
    }

    return found_if;
}
