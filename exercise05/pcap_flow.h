//
// Created by Alessandra Fais
// AED course - MCSN - University of Pisa
// A.A. 2017/18
//

#ifndef AED_LAB05_PCAP_FLOW_H
#define AED_LAB05_PCAP_FLOW_H

#include <pcap.h>
#include <strhash.h>
#include <string>
#include <tuple>
#include <unordered_set>
#include <unordered_map>

using namespace std;


// ------------------------------------flow definition----------------------------------------- //

/*
 * Flow fields are: source address, destination IP address, source port,
 * destination port and protocol.
 */
typedef tuple<u_int32_t, u_int32_t, u_int16_t, u_int16_t, string> key_f;

struct key_hash : public unary_function<key_f, size_t> {
    size_t operator()(const key_f& k) const {
        return get<0>(k) ^ get<1>(k) ^ get<2>(k) ^ get<3>(k) ^ hash<string>{}(get<4>(k));
    }
};

struct key_equal : public binary_function<key_f, key_f, bool> {
    bool operator()(const key_f& k1, const key_f& k2) const {
        return k1 == k2;
    }
};


// ------------------------------------map definition------------------------------------------ //

/*
 * Flow counter: (<key, value> unordered map) with key field the tuple that uniquely identifies
 * a flow and value field a counter of the packets belonging to that particular flow.
 */
typedef unordered_map<const key_f, unsigned long long, key_hash, key_equal> map_f;


// ------------------------------------class definition---------------------------------------- //

class Pcap_flow {
private:
    pcap_t* handle;
    map_f flows; // implements the flow counter

public:
    Pcap_flow(pcap_t* h);
    ~Pcap_flow();

    void sniff(int num_pkt);
    static void callback(u_char* user, const struct pcap_pkthdr* p_header, const u_char* packet);
    void handler(const struct pcap_pkthdr* p_header, const u_char* packet);
    string print_flow(const tuple<u_int32_t, u_int32_t, u_int16_t, u_int16_t, string>* t);
    void list();
};

#endif //AED_LAB05_PCAP_FLOW_H
