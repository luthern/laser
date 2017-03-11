#include <pbc.h>
#include <pbc_test.h>
#include <openssl/sha.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdbool.h>

int main();
void Hash1(element_t z1, element_t z2, element_t z);
void setPoint(element_t B0, element_t a1j);
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
	element_t h3;
	element_t g2;
	element_t omega;
};

struct membershipCredential {
	element_t J;
	element_t t;
	element_t d;
};

struct aliasCredential {
	element_t Ajk;
	element_t zjk;
	element_t yj;
	element_t xjk;
};

/* Signing credential is simply a list of ma aliasCredentials */
struct signingCredential {
	uint32_t entries;
	struct aliasCredential **aliasTokenList;
};

struct revocationListEntry {
	element_t a1i;
	element_t b2i;
	element_t Ki;
};

struct basenameRevocationList {
	uint32_t entries;
	struct revocationListEntry **revokedBasenameList;
};

struct xCoord {
	element_t xjk;
};

struct registryEntry {
	element_t a10;
	element_t b20;
	element_t K0;
	element_t xjk;
};

struct registry {
	uint32_t entries;
	struct registryEntry **registryEntries;
};

struct laserSignature {
	element_t xjk;
	element_t a1s;
	element_t b2s;
	element_t Ks;
	element_t T1;
	element_t T2;
	element_t T3;
	uint32_t nts;
	element_t cts;
	element_t sfs;
	element_t sz;
	element_t sdelta;
	element_t smu;
	element_t sv;
};

/* sigma_0 in GetSignCre */
struct membershipProof {
	element_t a10;
	element_t b20;
	element_t K0;
	element_t L;
	element_t U1;
	element_t U2;
	element_t U3;
	uint32_t nt0;
	element_t ct0;
	element_t sf0;
	element_t sy;
	element_t st;
	element_t stheta;
	element_t sxi;
	element_t snu;
};

/* sigma_i in GetSignCre */
struct basenameProof {
	element_t Pi;
	uint32_t nti;
	element_t cti;
	element_t staui;
	element_t svi;
};

struct sigmaG {
	struct membershipProof * sigma0;
	uint32_t entries;
	struct basenameProof ** proofsOfNonRevocation;
};

struct aliasTokenRevocationList {
	int entries;
};
