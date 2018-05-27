//
// Created by Alessandra Fais
// AED course - MCSN - University of Pisa
// A.A. 2017/18
//

#ifndef AED_LAB04_PCAP_IPSET_H
#define AED_LAB04_PCAP_IPSET_H

#include <pcap.h>
#include <unordered_set>

class Pcap_IPset {
public:
    Pcap_IPset(pcap_t* h);
    ~Pcap_IPset();

    void sniff(int num_pkt);
    static void callback(u_char* user, const struct pcap_pkthdr* p_header, const u_char* packet);
    void handler(const struct pcap_pkthdr* p_header, const u_char* packet);
    void list();

private:
    pcap_t* handle;
    std::unordered_set<u_int32_t> ipaddresses;
};

#endif //AED_LAB04_PCAP_IPSET_H
