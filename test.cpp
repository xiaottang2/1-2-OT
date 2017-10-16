#include <unistd.h>
#include <thread>
#include <cassert>
#include <string>
#include <sstream>
#include <iostream>
#include "ot.h"
#include "tcp.h"

static block cur_seed;
std::string block2hex(block a) {
    char buf[100];
    int cx;
    int64_t *v64val = (int64_t*) &a;
    cx = snprintf(buf, 100, "%.16llx %.16llx\n", (long long unsigned int)v64val[1], (long long unsigned int)v64val[0]);
    if (cx > 0 && cx <100) {
        return std::string(buf);
    }
    std::cerr << "Buffer overflow for block2hex()" << std::endl;
    exit(-1);
}
void printBignum(std::string s, BIGNUM* bn) {
    char* str = BN_bn2hex(bn);
    std::stringstream stream;
    stream << s << std::endl << str << std::endl << std::endl;
    std::cout << stream.str();
}
bool blockEq(block a, block b) {
    __m128i vcmp = (__m128i)_mm_cmpneq_ps(_mm_castsi128_ps(a), _mm_castsi128_ps(b)); // compare a, b for inequality
    uint16_t test = _mm_movemask_epi8(vcmp); // extract results of comparison
    if (test == 0xffff) // *all* elements not equal
        return false;
    else if (test != 0) // *some* elements not equal
        return false;
    else // no elements not equal, i.e. all elements equal
        return true;
}
void srand_sse( unsigned int seed ) {
    cur_seed = _mm_set_epi32( seed, seed+1, seed, seed+1 );
}

block random_block() {
    __m128i cur_seed_split;
    __m128i multiplier;
    __m128i adder;
    __m128i mod_mask;
    static const unsigned int mult[4] = { 214013, 17405, 214013, 69069 };
    static const unsigned int gadd[4] = { 2531011, 10395331, 13737667, 1 };
    static const unsigned int mask[4] = { 0xFFFFFFFF, 0, 0xFFFFFFFF, 0 };

    adder = _mm_load_si128( (__m128i*) gadd);
    multiplier = _mm_load_si128( (__m128i*) mult);
    mod_mask = _mm_load_si128( (__m128i*) mask);
    cur_seed_split = _mm_shuffle_epi32( cur_seed, _MM_SHUFFLE( 2, 3, 0, 1 ) );

    cur_seed = _mm_mul_epu32( cur_seed, multiplier );
    multiplier = _mm_shuffle_epi32( multiplier, _MM_SHUFFLE( 2, 3, 0, 1 ) );
    cur_seed_split = _mm_mul_epu32( cur_seed_split, multiplier );

    cur_seed = _mm_and_si128( cur_seed, mod_mask);
    cur_seed_split = _mm_and_si128( cur_seed_split, mod_mask );
    cur_seed_split = _mm_shuffle_epi32( cur_seed_split, _MM_SHUFFLE( 2, 3, 0, 1 ) );
    cur_seed = _mm_or_si128( cur_seed, cur_seed_split );
    cur_seed = _mm_add_epi32( cur_seed, adder);

    return cur_seed;
}

void testReceiver(int b_select, block label0, block label1) {
    int peer_sock = 0;
    for (int i = 0; i < 10; i++) {
        buildConnectionAsClient("127.0.0.1", 12345, peer_sock);
        block recv_label = recvOT(peer_sock, b_select);
        block target = b_select == 0 ? label0 : label1;
        block theother = b_select == 0 ? label1 : label0;
        if(!blockEq(recv_label, target)) {
            std::cerr << "OT failed." << std::endl;
            std::cerr << "Received:" << block2hex(recv_label) << std::endl;
            std::cerr << "Expecting:" << block2hex(target) << std::endl;
            std::cerr << "The other is:" << block2hex(theother) << std::endl;
        } else {
            std::cout << "OT succedded." << std::endl;
            std::cout << "Received:" << block2hex(recv_label) << std::endl;
            std::cout << "Expecting:" << block2hex(target) << std::endl;
            std::cout << "The other is:" << block2hex(theother) << std::endl;
        }
        close(peer_sock);
    }
}

void testSender(block label0, block label1) {
    int listen_sock = 0;
    int peer_sock = 0;
    for (int i = 0; i < 10; i++ ) {
        buildConnectionAsServer(12345, listen_sock, peer_sock);
        sendOT(peer_sock, label0, label1);
        close(listen_sock);
        close(peer_sock);
    }
}

void testOT() {
    srand_sse(time(NULL));
    random_block();
    block label0 = random_block();
    block label1 = random_block();
    std::thread tRecv(testReceiver, 0, label0, label1);
    testSender(label0, label1);
    tRecv.join();
}

int main() {
	testOT();
}
