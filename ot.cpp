#include <iostream>
#include <arpa/inet.h>
#include <emmintrin.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include "ot.h"

#ifndef MSG_MORE
#define MSG_MORE 0
#endif

#define LABELSIZE 16
typedef __m128i block;
void sendOT(int sock, block label0, block label1) {

    int ret = 0;
    RSA *r = NULL;
    BIGNUM *bn_x0 = BN_new();
    BIGNUM *bn_x1 = BN_new();
    BN_rand(bn_x0, RSA_bits, 0, 0);
    int len = BN_num_bytes(bn_x0);
    unsigned char x0_bin[len / sizeof(unsigned char)];
    unsigned char x1_bin[len / sizeof(unsigned char)];
    BIGNUM *bn_e = NULL;
    BIGNUM *bn_n = NULL;
    BIGNUM *bn_d = NULL;
    BIGNUM *bn_p = NULL;
    BIGNUM *bn_q = NULL;
    unsigned long e = 3;

    bn_e = BN_new();
    ret = BN_set_word(bn_e, e);
    if (ret != 1) {
        std::cerr << "BN_set_word() failed." << std::endl;
        exit(-1);
    }

	r = RSA_new();
    RSA_generate_key_ex(r, RSA_bits, bn_e, NULL);
    if (!ret) {
        std::cerr << "RSA_generate_key_ex() failed." << std::endl;
        exit(-1);
    }

    bn_n = r->n;
    bn_d = r->d;
    bn_p = r->p;
    bn_q = r->q;
    BN_CTX* actx = BN_CTX_new();

    int e_size = BN_num_bytes(bn_e);
    int n_size = BN_num_bytes(bn_n);
    unsigned char e_bin[e_size / sizeof(unsigned char)];
    unsigned char n_bin[n_size / sizeof(unsigned char)];

    BN_bn2bin(bn_e, e_bin);
    BN_bn2bin(bn_n, n_bin);

    // Send Public Key
    send(sock, &e_size, sizeof(int), MSG_MORE);
    send(sock, &n_size, sizeof(int), MSG_MORE);
    send(sock, &e_bin, e_size, MSG_MORE);
    send(sock, &n_bin, n_size, MSG_MORE);

    // Send random message size
    int msg_size = len;
    send(sock, &msg_size, sizeof(int), MSG_MORE);

    // Define additional variables
    int v_size;
    BIGNUM* bn_v = BN_new();
    BIGNUM* bn_k0 = BN_new();
    BIGNUM* bn_k1 = BN_new();

    int _m0_size;
    unsigned char *_m0_bin;
    BIGNUM* bn__m0 = BN_new();

    int _m1_size;
    unsigned char *_m1_bin;
    BIGNUM* bn__m1 = BN_new();

    BIGNUM* bn_v_sub_x0 = BN_new();
    BIGNUM* bn_v_sub_x1 = BN_new();
    BIGNUM* bn_label0 = BN_new();
    BIGNUM* bn_label1 = BN_new();

    BN_CTX* ctx = BN_CTX_new();

    // Convert InputLabelPairs to array of BIGNUMs

    BN_bin2bn((const unsigned char *)&label0, LABELSIZE, bn_label0);
    BN_bin2bn((const unsigned char *)&label1, LABELSIZE, bn_label1);

    // Perform 1-2-OT
    BN_rand(bn_x0, RSA_bits, 0, 0);
    BN_rand(bn_x1, RSA_bits, 0, 0);
    BN_bn2bin(bn_x0, x0_bin);
    BN_bn2bin(bn_x1, x1_bin);

    // Send random messages
    send(sock, x0_bin, len, MSG_MORE);
    send(sock, x1_bin, len, MSG_MORE);

    // Receive v size
    recv(sock, &v_size, sizeof(int), 0);
    unsigned char v_bin[v_size];
    recv(sock, &v_bin, v_size, 0);

    BN_bin2bn((const unsigned char*)v_bin, v_size, bn_v);

    BN_mod_sub(bn_v_sub_x0, bn_v, bn_x0, bn_n, ctx);
    BN_mod_exp(bn_k0, bn_v_sub_x0, bn_d, bn_n, ctx);

    BN_mod_sub(bn_v_sub_x1, bn_v, bn_x1, bn_n, ctx);
    BN_mod_exp(bn_k1, bn_v_sub_x1, bn_d, bn_n, ctx);

    BN_add(bn__m0, bn_k0, bn_label0);
    BN_add(bn__m1, bn_k1, bn_label1);

    _m0_size = BN_num_bytes(bn__m0);
    _m1_size = BN_num_bytes(bn__m1);
    _m0_bin = new unsigned char[_m0_size / sizeof(unsigned char)];
    _m1_bin = new unsigned char[_m1_size / sizeof(unsigned char)];

    BN_bn2bin(bn__m0, _m0_bin);
    BN_bn2bin(bn__m1, _m1_bin);

    // send encrypted messages
    send(sock, &_m0_size, sizeof(int), MSG_MORE);
    send(sock, &_m1_size, sizeof(int), MSG_MORE);
    send(sock, _m0_bin, _m0_size, MSG_MORE);
    send(sock, _m1_bin, _m1_size, MSG_MORE);

    delete[] _m0_bin;
    delete[] _m1_bin;

    BN_CTX_free(ctx);
    BN_free(bn_x0);
    BN_free(bn_x1);
    BN_free(bn_e);
    BN_free(bn_n);
    BN_free(bn_d);
    BN_free(bn_v);
    BN_free(bn_k0);
    BN_free(bn_k1);
    BN_free(bn__m0);
    BN_free(bn__m1);
    BN_free(bn_v_sub_x0);
    BN_free(bn_v_sub_x1);
    BN_free(bn_label0);
    BN_free(bn_label1);

}

block recvOT(int sock, int b_select) {
    unsigned char * x0_bin;
    unsigned char * x1_bin;
    unsigned char * _m0_bin;
    unsigned char * _m1_bin;
    unsigned char * mb_bin; // Binary for the final result
    BIGNUM *bn_e = BN_new();
    BIGNUM *bn_n = BN_new();
    BIGNUM *bn_xb_mod_n = BN_new();
    BIGNUM *bn_k_pow_e_mod_n = BN_new();
    BIGNUM *bn_v = BN_new();
    BIGNUM *bn_x0 = BN_new();
    BIGNUM *bn_x1 = BN_new();
    BIGNUM *bn_xb = NULL;
    BIGNUM *bn_k = BN_new();
    BIGNUM *bn__m0 = BN_new();
    BIGNUM *bn__m1 = BN_new(); //
    BIGNUM *bn__mb;
    BIGNUM *bn_mb = BN_new(); // BIGNUM for the final result
    BN_CTX *ctx = BN_CTX_new();
    int len, e_size, n_size, v_size;
    int _m0_size, _m1_size;
    block label;

    // Receive public key
    recv(sock, &e_size, sizeof(int), 0);
    recv(sock, &n_size, sizeof(int), 0);
    unsigned char e_bin[e_size];
    unsigned char n_bin[n_size];
    recv(sock, &e_bin, e_size, 0);
    recv(sock, &n_bin, n_size, 0);

    // Convert binary data to BIGNUM
    BN_bin2bn((const unsigned char*)e_bin, e_size, bn_e);
    BN_bin2bn((const unsigned char*)n_bin, n_size, bn_n);

    // Receive message size
    recv(sock, &len, sizeof(int), 0);

    // Receive x0_bin and x1_bin
    x0_bin = new unsigned char[len / sizeof(unsigned char)];
    x1_bin = new unsigned char[len / sizeof(unsigned char)];
    recv(sock, x0_bin, len, 0);
    recv(sock, x1_bin, len, 0);

    // Convert binary data to BIGNUM
    BN_bin2bn((const unsigned char*)x0_bin, len, bn_x0);
    BN_bin2bn((const unsigned char*)x1_bin, len, bn_x1);
    delete[] x0_bin;
    delete[] x1_bin;

    // Generate random K
    BN_rand(bn_k, RSA_bits,0, 0);

    // Compute v=(x_b + k^e) mod N
    bn_xb = b_select == 0 ? bn_x0 : bn_x1;
    BN_mod(bn_xb_mod_n, bn_xb, bn_n, ctx);
    BN_mod_exp(bn_k_pow_e_mod_n, bn_k, bn_e, bn_n, ctx);
    BN_mod_add(bn_v, bn_xb_mod_n, bn_k_pow_e_mod_n, bn_n, ctx);

    // Convert v to binary data and send v
    v_size = BN_num_bytes(bn_v);
    unsigned char v_bin[v_size];
    BN_bn2bin(bn_v, v_bin);
    send(sock, &v_size, sizeof(int), MSG_MORE);
    send(sock, &v_bin, v_size, MSG_MORE);

    // Receive _m0 and _m1
    recv(sock, &_m0_size, sizeof(int), 0);
    recv(sock, &_m1_size, sizeof(int), 0);
    _m0_bin = new unsigned char[_m0_size];
    _m1_bin = new unsigned char[_m1_size];
    recv(sock, _m0_bin, _m0_size, 0);
    recv(sock, _m1_bin, _m1_size, 0);

    // Convert binary data to BIGNUM
    BN_bin2bn((const unsigned char*)_m0_bin, _m0_size, bn__m0);
    BN_bin2bn((const unsigned char*)_m1_bin, _m1_size, bn__m1);
    delete[] _m0_bin;
    delete[] _m1_bin;

    // Compute mb = _mb-k
    bn__mb = b_select == 0 ? bn__m0 : bn__m1;
    BN_sub(bn_mb, bn__mb, bn_k);

    // Convert BIGNUM to label and stores it. Note: bn_mb is guaranteed to be 128 bit in size
    mb_bin = new unsigned char[BN_num_bytes(bn_mb) / sizeof(unsigned char)];
    BN_bn2bin(bn_mb, mb_bin);
    label = _mm_load_si128((__m128i *)mb_bin);

    delete[] mb_bin;
    BN_CTX_free(ctx);
    BN_free(bn_e);
    BN_free(bn_n);
    BN_free(bn_xb_mod_n);
    BN_free(bn_k_pow_e_mod_n);
    BN_free(bn_v);
    BN_free(bn_x0);
    BN_free(bn_x1);
    BN_free(bn_k);
    BN_free(bn__m0);
    BN_free(bn__m1);
    BN_free(bn_mb);

    return label;
}
