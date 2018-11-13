//
// Created by Alessandra Fais
// AED course - MCSN - University of Pisa
// A.A. 2017/18
//

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <cstring>
#include <stdexcept>
#include <tuple>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/igmp.h>

#include "pcap_flow.h"
#include "utils.h"

using namespace std;

/*
 * Constructor.
 * \throw std::invalid_argument exception if the pcap handle is NULL
 */
Pcap_flow::Pcap_flow(pcap_t *h) {
    if (h != nullptr) {
        handle = h;
        bloomfilter = new CountingBF(100, 2);
    }
    else throw invalid_argument("pcap handle is null");
}

Pcap_flow::~Pcap_flow() {
    pcap_close(handle);
}

/*
 * Method that captures packets until the given number of wanted packets is reached (num_pkt parameter)
 * or the end of the file is reached (in the case in which pcap_open_offline() is used).
 */
void Pcap_flow::sniff(int num_pkt) {
    if (pcap_loop(handle, num_pkt, callback, reinterpret_cast<u_char*>(this)) == -1) {
        cerr << "pcap loop failed" << endl;
        abort();
    }
}

/*
 * Method called on per-packet basis.
 */
void Pcap_flow::callback(u_char* user, const struct pcap_pkthdr* p_header, const u_char* packet) {
    Pcap_flow* that = reinterpret_cast<Pcap_flow*>(user);
    that->handler(p_header, packet);
}

/*
 * Packet handler method.
 */
void Pcap_flow::handler(const struct pcap_pkthdr* p_header, const u_char* packet) {
    // Parse packet
    const struct ether_header* e_hdr = reinterpret_cast<const struct ether_header*>(packet);
    const struct vlan_ethhdr* vlan_hdr = nullptr;
    if (ntohs(e_hdr->ether_type) == ETHERTYPE_VLAN)
        vlan_hdr = reinterpret_cast<const struct vlan_ethhdr*>(packet);

    const struct ip* ip_hdr = (vlan_hdr) ?
                              reinterpret_cast<const struct ip*>(vlan_hdr + 1) :
                              reinterpret_cast<const struct ip*> (e_hdr + 1);

    int offset = (ip_hdr->ip_hl) * 4;
    const struct udphdr* udp_hdr = reinterpret_cast<const struct udphdr*>(reinterpret_cast<const char*>(ip_hdr) + offset);
    const struct tcphdr* tcp_hdr = reinterpret_cast<const struct tcphdr*>(reinterpret_cast<const char*>(ip_hdr) + offset);

    u_int32_t ip_src = reinterpret_cast<u_int32_t>(ip_hdr->ip_src.s_addr);
    u_int32_t ip_dst = reinterpret_cast<u_int32_t>(ip_hdr->ip_dst.s_addr);
    string prot;
    u_int16_t port_src = 0;
    u_int16_t port_dst = 0;

    switch (ip_hdr->ip_p) {
        case IPPROTO_UDP:
            port_src = reinterpret_cast<u_int16_t>(ntohs(udp_hdr->uh_sport));
            port_dst = reinterpret_cast<u_int16_t>(ntohs(udp_hdr->uh_dport));
            prot = "UDP";
            break;
        case IPPROTO_TCP:
            port_src = reinterpret_cast<u_int16_t>(ntohs(tcp_hdr->th_sport));
            port_dst = reinterpret_cast<u_int16_t>(ntohs(tcp_hdr->th_dport));
            prot = "TCP";
            break;
        case IPPROTO_ICMP:
            prot = "ICMP";
            break;
        case IPPROTO_IGMP:
            prot = "IGMP";
            break;
        default:
            break;
    }

    // insert a new flow in the map or increment the number of packets for an existing flow
    const key_f key = make_tuple(ip_src, ip_dst, port_src, port_dst, prot);
    if (flows.count(key) == 0)
        flows[key] = 1;
    else
        flows[key]++;

    // add the flow in the bloom filter
    ostringstream buf;
    buf << ip_src << ip_dst << port_src << port_dst << prot; // serialize the flow tuple
    bloomfilter->add(buf.str().c_str(), strlen(buf.str().c_str()));
}

/*
 * Construct a string from the flow tuple.
 */
pair<string, string> print_flow(const key_f* t) {
    u_int32_t ipsrc, ipdst;
    u_int16_t psrc, pdst;
    string prot;
    tie(ipsrc, ipdst, psrc, pdst, prot) = *t; // unpacks the tuple into individual objects

    char ip_src[16];
    char ip_dst[16];
    inet_ntop(AF_INET, reinterpret_cast<const void*>(&ipsrc), ip_src, sizeof(ip_src));
    inet_ntop(AF_INET, reinterpret_cast<const void*>(&ipdst), ip_dst, sizeof(ip_dst));

    stringstream ss;
    ss << setw(17) << left
       << ip_src
       << setw(17) << left
       << ip_dst
       << setw(11) << left
       << ntohs(psrc)
       << setw(12) << left
       << ntohs(pdst)
       << setw(13) << left
       << prot;

    ostringstream buf;
    buf << ipsrc << ipdst << psrc << pdst << prot; // serialize the flow tuple
    return pair<string, string>(ss.str(), buf.str());
}

/*
 * Print the list of flows.
 */
void Pcap_flow::list() {
    std::cout << "Found "
              << flows.size() // number of different flows
              << " different flows.\n"
              << "List of flows: \n"
              << setw(17) << left
              << "IPsrc"
              << setw(17) << left
              << "IPdst"
              << setw(11) << left
              << "Port src"
              << setw(11) << left
              << "Port dst"
              << setw(11) << left
              << "Protocol"
              << setw(11) << left
              << "pkt_count"
              << setw(11) << left
              << "bf_value"
              << setw(10) << left
              << "cbf_value\n";
    for (const auto f : flows) {
        pair<string, string> p = print_flow(&f.first);
        cout << p.first // flow tuple
             << setw(12) << left
             << f.second // number of packets per flow
             << setw(11) << left
             << bloomfilter->lookup(p.second.c_str(), strlen(p.second.c_str())) // bloom filter value {0, 1}
             << setw(6) << left
             << bloomfilter->counting_lookup(p.second.c_str(), strlen(p.second.c_str())) // counting bloom filter value
             << endl;
    }
    bloomfilter->bf_printstate();
    bloomfilter->countingbf_printstate();
}
