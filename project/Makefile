CXX      = g++
CXXFLAGS = -Wall -Wextra -std=c++11
INCLUDES = -I /usr/include/pcap -I ./smhasher/
LIBFLAGS = -lpcap
OPTFLAGS = -O3

DEPS = counting_bloomfilter.h pcap_flow.h utils.h
OBJS = counting_bloomfilter.o main.o pcap_flow.o ./smhasher/src/MurmurHash3.o

.PHONY: main clean cleanall

%.o: %.cpp $(DEPS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(OPTFLAGS) $(LIBFLAGS) -c -o $@ $<

main: $(OBJS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(OPTFLAGS) $(LIBFLAGS) -o $@ $^

clean:
	rm -f $(OBJS)

cleanall: clean
	rm -f *.o *~