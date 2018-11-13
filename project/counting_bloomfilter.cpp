//
// Created by Alessandra Fais
// AED course - MCSN - University of Pisa
// A.A. 2017/18
//

#include <iostream>
#include <array>

#include "counting_bloomfilter.h"
#include "src/MurmurHash3.h"

/*
 * Constructor: takes the BF size and the number of hash functions to be used
 * as parameters.
 */
CountingBF::CountingBF(unsigned long size, unsigned short num_hashes)
        : bf(size), counting_bf(size), m(num_hashes) {}

/*
 * Use MurmurHash3 function to calculate the 128 bit hash of a given item.
 * Since we need 2 64 bit hashes, we split the returned hash in half to get
 * hashA(x) and hashB(x) (in order to store 128 bits we use 2 locations of 64 bits each).
 */
std::array<unsigned long, 2> hash(const char* key, const long len) {
    std::array<unsigned long, 2> hash_values;
    MurmurHash3_x64_128(key, len, 1, hash_values.data());
    return hash_values;
}

/*
 * Return the output of the n-th hash function.
 */
unsigned long nth_hash(unsigned short n,
                       unsigned long hashA,
                       unsigned long hashB,
                       unsigned long bf_size) {
    return (hashA + n * hashB) % bf_size;
}

void CountingBF::add(const char* key, const long len) {
    std::array<unsigned long, 2> hash_values = hash(key, len);

    for (int n = 0; n < m; n++) {
        bf[nth_hash(n, hash_values[0], hash_values[1], bf.size())] = true;
        counting_bf[nth_hash(n, hash_values[0], hash_values[1], counting_bf.size())] += 1;
    }
}

bool CountingBF::lookup(const char* key, const long len) const {
    std::array<unsigned long, 2> hash_values = hash(key, len);

    for (int n = 0; n < m; n++) {
        if (!bf[nth_hash(n, hash_values[0], hash_values[1], bf.size())])
            return false;
    }
    return true;
}

unsigned long CountingBF::counting_lookup(const char *key, const long len) const {
    std::array<unsigned long, 2> hash_values = hash(key, len);

    unsigned long min_count = 0;
    for (int n = 0; n < m; n++) {
        unsigned long nth = nth_hash(n, hash_values[0], hash_values[1], counting_bf.size());
        if (min_count == 0) min_count = counting_bf[nth];
        else if (min_count > counting_bf[nth] && counting_bf[nth] != 0) // take as best approximation the min value between all non-zero counters set for the same key
            min_count = counting_bf[nth];
    }
    return min_count;
}

void CountingBF::bf_printstate() {
    std::cout << "Bloom Filter state:\n[ ";
    for (auto b : bf) {
        std::cout << b << " ";
    }
    std::cout << "]\n";
}

void CountingBF::countingbf_printstate() {
    std::cout << "Counting Bloom Filter state:\n[ ";
    for (auto b : counting_bf) {
        std::cout << b << " ";
    }
    std::cout << "]\n";
}