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

int main(int argc, char* argv[]) {

    pcap_t* handle;
    char err_buf2[PCAP_ERRBUF_SIZE];
    int snaplen = 64;
    int promisc = 1;
    int ms = 10000;

    if (argc < 2) {
        std::cerr << "Usage: "
                  << argv[0]
                  << " <interface>"
                  << std::endl;
        return 1;
    }

    // Check if the interface passed as parameter is valid
    if (!find_dev(argv[1])) {
        std::cerr << "invalid network device" << std::endl;
        print_devs();
        return 1;
    }

    // Open a pcap descriptor
    handle = pcap_open_live(argv[1], snaplen, promisc, ms, err_buf2);
    if (handle == nullptr) {
        std::cerr << "pcap handle is null: couldn't open the device"
                  << err_buf2
                  << std::endl;
        return 1;
    }

    // Read packet
    struct pcap_pkthdr p_header;
    const u_char* packet = pcap_next(handle, &p_header);
    if (packet == nullptr) {
        std::cerr << "pcap packet is null" << std::endl;
        return 1;
    }

    // Print pcap packet header (metadata)
    char buf[20];
    strftime(buf, sizeof(buf), "%d/%m/%Y %H:%M:%S", localtime(&p_header.ts.tv_sec));
    std::cout << "pcap packet:"
              << std::endl
              << "- timestamp: "
              << buf
              << "."
              << p_header.ts.tv_usec
              << std::endl
              << "- len portion read: "
              << p_header.caplen
              << std::endl
              << "- len packet: "
              << p_header.len
              << std::endl
              << std::endl;

    // --------------------------- assume no VLAN traffic -------------------------------------

    // Parse the ethernet header (check the protocol type field, we want it to be IP)
    const struct ether_header* e_hdr = reinterpret_cast<const struct ether_header *> (packet);
    std::cout << "ETH header: "
              << ether_ntoa(reinterpret_cast<const ether_addr*>(e_hdr->ether_shost))
              << " --> "
              << ether_ntoa(reinterpret_cast<const ether_addr*>(e_hdr->ether_dhost))
              << std::endl;
    if (ntohs(e_hdr->ether_type) != ETHERTYPE_IP) { // network to host byte order conversion
        std::cerr << "not an IP packet" << std::endl;
        return 1;
    }

    // Parse the ip header
    const struct ip* ip_hdr = reinterpret_cast<const struct ip *> (e_hdr + 1);
    char ip_src[16]; // 15 char needed to represent the IP address in dot notation a.b.c.d
    char ip_dst[16];
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
              << ")"
              << std::endl;

    if (ip_hdr->ip_p == IPPROTO_UDP) {
        const struct udphdr* udp_hdr = reinterpret_cast<const struct udphdr*> (ip_hdr + 1);
        std::cout << "UDP packet: "
                  << ntohs(udp_hdr->uh_sport)
                  << " --> "
                  << ntohs(udp_hdr->uh_dport)
                  << std::endl;
    }

    if (ip_hdr->ip_p == IPPROTO_TCP) {
        const struct tcphdr* tcp_hdr = reinterpret_cast<const struct tcphdr*> (ip_hdr + 1);
        std::cout << "TCP packet: "
                  << ntohs(tcp_hdr->th_sport)
                  << " --> "
                  << ntohs(tcp_hdr->th_dport)
                  << std::endl;
    }

    if (ip_hdr->ip_p == IPPROTO_ICMP) {
        const struct icmp* icmp_hdr = reinterpret_cast<const struct icmp*> (ip_hdr + 1);
        std::cout << "ICMP packet: type "
                  << icmp_hdr->icmp_type
                  << ", code "
                  << icmp_hdr->icmp_code
                  << std::endl;
    }

    if (ip_hdr->ip_p == IPPROTO_IGMP) {
        const struct igmp* igmp_hdr = reinterpret_cast<const struct igmp*> (ip_hdr + 1);
        std::cout << "IGMP packet: type "
                  << ntohs(igmp_hdr->igmp_type)
                  << ", code "
                  << ntohs(igmp_hdr->igmp_code)
                  << std::endl;
    }

    return 0;
}