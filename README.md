# aed-18
Lab exercises of the Packet Switching and Processing Architectures course of the Computer Science and Networking Master's Degree @ University of Pisa

| <b>Lab number</b> | <b>Language/Framework/Tool</b> | <b>Description</b> |
| ---------- | ----------------------- | ----------- |
| 1 | C++, libpcap | Simple program that takes an interface as input parameter. It first checks if the interface is in the list of devices returned by `pcap_findalldevs()`: if yes it calls the `pcap_open_live()` on that interface, otherwise a valid interface is requested. Once the device has been correctly opened a packet will be captured and some information on its content will be printed out. |