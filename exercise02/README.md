### Requirements
The libpcap library is required.

### Compile and run
Compilation:

```g++ -Wall -Wextra -std=c++11 -I /usr/include/pcap main.cpp -lpcap -O3 -o main```

Run:

```./main pcap-filename```