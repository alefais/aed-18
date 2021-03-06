# aed-18: exercises and final project 
Lab exercises and final project of the Packet Switching and Processing Architectures course of the Computer Science and Networking Master's Degree @ University of Pisa.

| <b>Exercise number</b> | <b>Language/Framework/Tool</b> | <b>Description</b> |
| ---------- | ----------------------- | ----------- |
| 1 | C++, libpcap | A simple program that takes an interface as input parameter. It first checks if the interface is in the list of devices returned by `pcap_findalldevs()`: if yes it calls the `pcap_open_live()` on that interface, otherwise a valid interface is requested. Once the descriptor has been correctly opened a packet will be captured with the `pcap_next()` and some information on its content will be printed out. |
| 2 | C++, libpcap | A simple program that takes a pcap file as input parameter. A descriptor is obtained with the `pcap_open_offline()`. The `pcap_next()` is used and some information on the content of the captured packet will be printed out. VLAN traffic ([IEEE 802.1Q](https://en.wikipedia.org/wiki/IEEE_802.1Q)) has been managed. |
| 3 | C++, libpcap | A simple program that takes as input parameters a pcap file and the number of packets to be captured. A descriptor is obtained with the `pcap_open_offline()`. The `pcap_loop()` is used and a packet handler callback is defined. The callback is supposed to be called on a per-packet basis and implements the parsers of the protocol headers. |
| 4 | C++, libpcap | A program that obtains packets from a pcap file and does some analysis. It requires as input parameters a pcap file and the number of packets to be captured. The computation returns the number (and the list) of the different source IP addresses found in the analyzed traffic. |
<!---
| 5 | C++, libpcap | A program that uses the [pcap]() library to capture some traffic and identifies and analyzes different flows. The user can specify as input parameters both a network interface or a pcap capture file, along with the number of packets that he wants to analyze. In the first case the capture is done using the `pcap_open_live()` while in the second case the `pcap_open_offline()` is used. The aim of the program is to identify different flows (where a flow is a tuple composed by source IP address, destination IP address, source port, destination port and protocol) and to count how many packets belong to a certain flow. <br>Two different implementations are provided: <ul><li>an unordered map where the keys are the flow tuples and the values are the packet counters for each flow; only C++ base mechanism and library are used in this case.</li><li>a counting bloom filter randomized data structure used to both check set membership for the flows and count the packets per flow; the [MurmurHash3]() function has been used in order to produce 128-bit hash values efficiently.</li></ul> The program output is a table containing a summary of the results produced by the two approaches and showing consistency between them: for each flow the number of counted packets (stored in the map) is printed out along with the counter values retrieved from the bloom filter. |
-->


## Final project

An application that uses the [pcap](https://github.com/the-tcpdump-group/libpcap) library to capture traffic, identifying and analyzing different flows. The user can specify as input parameters both a network interface or a pcap capture file, along with the number of packets that he/she wants to analyze. In the first case the analysis is performed on traffic that appears live in the monitoring application, while in the second case the content of the capture file is inspected in offline mode. 


The aim of the program is to identify different *flows* (a flow is defined by a tuple ```<source IP address, destination IP address, source port, destination port, protocol>```) and to count how many packets belong to a certain flow. 


Two different implementations are provided: <ul>
	<li>an unordered map where a *key* is a flow tuple and a *value* is the packet counter for that specific flow entry; C++ base mechanism only are used in this case</li>
	<li>a counting bloom filter randomized data structure used to both check set membership for the flows and count the packets per flow; one of the [MurmurHash3](https://github.com/aappleby/smhasher) functions has been used in order to produce 128-bit hash values efficiently</li>
</ul> 
The program output is a table that summarizes the results produced by the two approaches and shows consistency between them: for each flow the number of counted packets (stored in the map) is printed out along with the counter values retrieved from the bloom filter.
