//
// Created by Alessandra Fais
// AED course - MCSN - University of Pisa
// A.A. 2017/18
//

#ifndef AED_LAB05_COUNTING_BLOOMFILTER_H
#define AED_LAB05_COUNTING_BLOOMFILTER_H

#include <vector>

class CountingBF {
public:
    CountingBF(unsigned long size, unsigned short num_hashes);
    ~CountingBF();
    void add (const char* key, const long len);
    bool lookup(const char* key, const long len) const;
    unsigned long counting_lookup(const char* key, const long len) const;
    void bf_printstate();
    void countingbf_printstate();

private:
    unsigned short m; // number of hash functions to use
    std::vector<bool> bf; // bloom filter vector
    std::vector<unsigned long> counting_bf; // counting bloom filter vector
};

#endif //AED_LAB05_COUNTING_BLOOMFILTER_H
