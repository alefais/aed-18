CXX      = g++
CXXFLAGS = -Wall -Wextra -std=c++11
INCLUDES = -I /usr/include/pcap
LIBFLAGS = -lpcap
OPTFLAGS = -O3

DEPS = pcap_ipset.h utils.h
OBJS = main.o pcap_ipset.o

.PHONY: main clean cleanall

%.o: %.cpp $(DEPS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(OPTFLAGS) $(LIBFLAGS) -c -o $@ $<

main: $(OBJS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(OPTFLAGS) $(LIBFLAGS) -o $@ $^

clean:
	rm -f $(OBJS)

cleanall: clean
	rm -f *.o *~