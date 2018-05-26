//
// Created by Alessandra Fais
// AED course - MCSN - University of Pisa
// A.A. 2017/18
//

#ifndef AED_LAB03_UTILS_H
#define AED_LAB03_UTILS_H

#include <iostream>
#include <pcap.h>
#include <net/ethernet.h>

struct vlan_ethhdr {
    u_char h_dest[ETHER_ADDR_LEN];
    u_char h_source[ETHER_ADDR_LEN];
    u_int16_t h_vlan_proto;
    u_int16_t h_vlan_TCI;
    u_int16_t h_vlan_encapsulated_proto;
};

void pkt_handler_callback(u_char* user_data, const struct pcap_pkthdr* p_header, const u_char* packet);

#endif //AED_LAB03_UTILS_H
