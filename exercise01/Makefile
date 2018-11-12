CXX      = g++-8
CXXFLAGS = -Wall -Wextra -std=c++11
INCLUDES = -I /usr/include/pcap
LIBFLAGS = -lpcap
OPTFLAGS = -O3

DEPS = utils.h
OBJS = main.o utils.o

.PHONY: main clean cleanall

%.o: %.cpp $(DEPS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(OPTFLAGS) $(LIBFLAGS) -c -o $@ $<

main: $(OBJS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) $(OPTFLAGS) $(LIBFLAGS) -o $@ $^

clean:
	rm -f $(OBJS)

cleanall: clean
	rm -f *.o *~