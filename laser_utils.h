#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pbc.h>
#include <pbc_test.h>
#include <openssl/sha.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>

#define PORT 3490
#define MAXSIZE 512
#define BACKLOG 10

typedef struct {
	field_ptr field;
	element_t a, b;
	mpz_ptr cofac;
	element_t gen_no_cofac;
	element_t gen;
	mpz_ptr quotient_cmp;
} * curve_data_ptr;

typedef struct {
	int inf_flag;
	element_t x, y;
} * point_ptr;

int main(int argc, char *argv[]);
/*
 * Sets elem to be a point on the curve such that
 * preimg's data is the preimage of the x parameter of the curve
 * Requires both to be initialized, elem on ECC group, preimg on Zr
 */
void generate_x_check_ecc(element_ptr elem, element_t preimg);

