//
// Created by Alessandra Fais
// AED course - MCSN - University of Pisa
// A.A. 2017/18
//

#include <iostream>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/igmp.h>

#include "utils.h"

// Function called on per-packet basis
void pkt_handler_callback(u_char* user_data, const struct pcap_pkthdr* p_header, const u_char* packet) {
    // Print pcap packet header
    char buf[20];
    strftime(buf, sizeof(buf), "%d/%m/%Y %H:%M:%S", localtime(&p_header->ts.tv_sec));
    std::cout << "pcap packet:"
              << std::endl
              << "- timestamp: "
              << buf
              << "."
              << p_header->ts.tv_usec
              << std::endl
              << "- len portion read: "
              << p_header->caplen
              << std::endl
              << "- len packet: " // if VLAN it counts 14 bytes (ETH header) + 4 bytes (802.1q header) + IP pkt len
              << p_header->len
              << std::endl
              << std::endl;

    // Parse packet
    const struct ether_header* e_hdr = reinterpret_cast<const struct ether_header*>(packet);
    const struct vlan_ethhdr* vlan_hdr = nullptr;
    if (ntohs(e_hdr->ether_type) == ETHERTYPE_VLAN) {
        vlan_hdr = reinterpret_cast<const struct vlan_ethhdr*>(packet);
        std::cout << "vlan_proto: "
                  << std::hex << ntohs(vlan_hdr->h_vlan_proto) << std::dec
                  << " vlan_TCI: "
                  << ntohs(vlan_hdr->h_vlan_TCI)
                  << std::endl;
    }
    else if (ntohs(e_hdr->ether_type) != ETHERTYPE_IP) {
        std::cerr << "not an IP packet" << std::endl;
        std::abort();
    }

    std::cout << "ETH header: "
              << ether_ntoa(reinterpret_cast<const ether_addr*>(e_hdr->ether_shost))
              << " --> "
              << ether_ntoa(reinterpret_cast<const ether_addr*>(e_hdr->ether_dhost))
              << std::endl;

    const struct ip* ip_hdr = (vlan_hdr) ?
                              reinterpret_cast<const struct ip*>(vlan_hdr + 1) :
                              reinterpret_cast<const struct ip*> (e_hdr + 1);
    char ip_src[16]; // 15 char needed to represent the IP address in dot notation a.b.c.d
    char ip_dst[16];
    int offset = (ip_hdr->ip_hl) * 4;
    inet_ntop(AF_INET, reinterpret_cast<const void *>(&ip_hdr->ip_src), ip_src, sizeof(ip_src));
    inet_ntop(AF_INET, reinterpret_cast<const void *>(&ip_hdr->ip_dst), ip_dst, sizeof(ip_dst));
    std::cout << "IP header (version "
              << ip_hdr->ip_v
              << "): "
              << ip_src
              << " --> "
              << ip_dst
              << "  (ttl = "
              << (int)ip_hdr->ip_ttl
              << ", frame_len = "
              << ntohs(ip_hdr->ip_len)
              << ", hdr_len = "
              << offset
              << ")"
              << std::endl;

    const struct udphdr* udp_hdr = reinterpret_cast<const struct udphdr*>(reinterpret_cast<const char*>(ip_hdr) + offset);
    const struct tcphdr* tcp_hdr = reinterpret_cast<const struct tcphdr*>(reinterpret_cast<const char*>(ip_hdr) + offset);
    const struct icmp* icmp_hdr = reinterpret_cast<const struct icmp*>(reinterpret_cast<const char*>(ip_hdr) + offset);
    const struct igmp* igmp_hdr = reinterpret_cast<const struct igmp*>(reinterpret_cast<const char*>(ip_hdr) + offset);
    switch (ip_hdr->ip_p) {
        case IPPROTO_UDP:
            std::cout << "UDP packet: "
                      << ntohs(udp_hdr->uh_sport)
                      << " --> "
                      << ntohs(udp_hdr->uh_dport)
                      << std::endl;
            break;
        case IPPROTO_TCP:
            std::cout << "TCP packet: "
                      << ntohs(tcp_hdr->th_sport)
                      << " --> "
                      << ntohs(tcp_hdr->th_dport)
                      << std::endl;
            break;
        case IPPROTO_ICMP:
            std::cout << "ICMP packet: type "
                      << icmp_hdr->icmp_type
                      << ", code "
                      << icmp_hdr->icmp_code
                      << std::endl;
            break;
        case IPPROTO_IGMP:
            std::cout << "IGMP packet: type "
                      << igmp_hdr->igmp_type
                      << ", code "
                      << igmp_hdr->igmp_code
                      << std::endl;
            break;
        default:
            break;
    }
    std::cout << "\n------------------------------------------------------------------------------\n";
}
