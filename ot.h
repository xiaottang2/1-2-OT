#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <sys/socket.h>
#include <emmintrin.h>
typedef __m128i block;
#define RSA_bits 2048
void sendOT(int sock, block label0, block label1);
block recvOT(int sock, int b_select);