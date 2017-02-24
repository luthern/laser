#include <pbc.h>
#include <pbc_test.h>
#include <openssl/sha.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdbool.h>

int main();
void Hash1(element_t z1, element_t z2, element_t z);
void setPoint(element_t Bj, element_t a1j);
void Hash2(element_t z, element_t B, element_t K, element_t L, element_t Uo,
	   element_t Ut, element_t Ue, element_t Ro, element_t Rt, element_t Re,
	   element_t Rf, int q);
	
const char *bncurve = "type f q 115792089237314936872688561244471742058375878355761205198700409522629664518163 r 115792089237314936872688561244471742058035595988840268584488757999429535617037 b 3 beta 2 alpha0 -2 alpha1 1";

const int l1 = 64, lt = 384, lz = 32;

unsigned char ibuf[2500];
unsigned char jbuf[500];
unsigned char obuf[128];

typedef struct {
 	field_ptr field;
	element_t a, b;
	mpz_ptr cofac;
	element_t gen_no_cofac;
	element_t gen;
	mpz_ptr quotient_cmp;
} *curve_data_ptr;

typedef struct {
	int inf_flag;
	element_t x, y;
} *point_ptr;

struct groupPublicKey {
	element_t g1;
	element_t h1;
	element_t h2;
	element_t chi;
	element_t g2;
	element_t omega;
};

struct membershipCredential {
	element_t J;
	element_t z;
	element_t rho;
};

struct aliasCredential {
	element_t Ajk;
	element_t xjk;
	element_t yjk;
};

/* Signing credential is simply a list of ma aliasCredentials */
struct signingCredential {
	uint32_t entries;
	struct aliasCredential *aliasTokenList;
};

struct revocationListEntry {
	element_t a2i;
	element_t b2i;
	element_t Ki;
};

struct basenameRevocationList {
	uint32_t entries;
	struct revocationListEntry *revokedBasenameList;
};

struct laserSignature {
	element_t xjk;
	element_t t2;
	element_t d2;
	element_t E;
	element_t T1;
	element_t T2;
	element_t T3;
	uint32_t nts;
	element_t cts;
	element_t sfs;
	element_t sdelta;
	element_t smu;
	element_t sv;
	element_t spsi;
};
