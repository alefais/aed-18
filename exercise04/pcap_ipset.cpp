//
// Created by Alessandra Fais
// AED course - MCSN - University of Pisa
// A.A. 2017/18
//

#include <iostream>
#include <stdexcept>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/igmp.h>

#include "pcap_ipset.h"
#include "utils.h"

/*
 * Constructor.
 * \throw std::invalid_argument exception if the pcap handle is NULL
 */
Pcap_IPset::Pcap_IPset(pcap_t *h) {
    if (h != nullptr) handle = h;
    else throw std::invalid_argument("pcap handle is null");
}

Pcap_IPset::~Pcap_IPset() {
    pcap_close(handle);
}

/*
 * Method that captures packets until the given number of wanted packets is reached (num_pkt parameter)
 * or the end of the file is reached (since pcap_open_offline() is used).
 */
void Pcap_IPset::sniff(int num_pkt) {
    if (pcap_loop(handle, num_pkt, callback, reinterpret_cast<u_char*>(this)) == -1) {
        std::cerr << "pcap loop failed" << std::endl;
        std::abort();
    }
}

/*
 * Method called on per-packet basis.
 */
void Pcap_IPset::callback(u_char* user, const struct pcap_pkthdr* p_header, const u_char* packet) {
    Pcap_IPset* that = reinterpret_cast<Pcap_IPset*>(user);
    that->handler(p_header, packet);
}

/*
 * Packet handler method.
 */
void Pcap_IPset::handler(const struct pcap_pkthdr* p_header, const u_char* packet) {
    // Parse packet
    const struct ether_header* e_hdr = reinterpret_cast<const struct ether_header*>(packet);
    const struct vlan_ethhdr* vlan_hdr = nullptr;
    if (ntohs(e_hdr->ether_type) == ETHERTYPE_VLAN)
        vlan_hdr = reinterpret_cast<const struct vlan_ethhdr*>(packet);

    const struct ip* ip_hdr = (vlan_hdr) ?
                              reinterpret_cast<const struct ip*>(vlan_hdr + 1) :
                              reinterpret_cast<const struct ip*> (e_hdr + 1);

    // Update the set of IP addresses (duplicates are implicitly managed by the data structure)
    ipaddresses.insert(reinterpret_cast<uint32_t>(ip_hdr->ip_src.s_addr));
}

/*
 * Print the list of IP addresses found.
 */
void Pcap_IPset::list() {
    std::cout << "Found "
              << ipaddresses.size()
              << " different IP addresses\n"
              << "List of IP addresses: \n";
    for (auto ipaddr : ipaddresses) {
        char ip_src[16];
        inet_ntop(AF_INET, &ipaddr, ip_src, sizeof(ip_src));
        std::cout << ip_src << std::endl;
    }
}

