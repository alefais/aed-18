# aed-18
Lab exercises of the Packet Switching and Processing Architectures course of the Computer Science and Networking Master's Degree @ University of Pisa

| <b>Lab number</b> | <b>Language/Framework/Tool</b> | <b>Description</b> |
| ---------- | ----------------------- | ----------- |
| 1 | C++, libpcap | Simple program that takes an interface as input parameter. It first checks if the interface is in the list of devices returned by `pcap_findalldevs()`: if yes it calls the `pcap_open_live()` on that interface, otherwise a valid interface is requested. Once the descriptor has been correctly opened a packet will be captured with the `pcap_next()` and some information on its content will be printed out. |
| 2 | C++, libpcap | Simple program that takes a pcap file as input parameter. A descriptor is obtained with the `pcap_open_offline()`. Once it has been correctly opened a packet will be captured with the `pcap_next()` and some information on its content will be printed out. VLAN traffic ([IEEE 802.1Q](https://en.wikipedia.org/wiki/IEEE_802.1Q)) has been managed. |
| 3 | C++, libpcap | Simple program that takes as input parameters a pcap file and the number of packets to be captured. A descriptor is obtained with the `pcap_open_offline()`. The `pcap_loop()` is used in order to capture the packets that are then processed. |
| 4 | C++, libpcap | |