#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <tss2/tss.h>
#include <tss2/tssutils.h>
#include <tss2/tssmarshal.h>
#include <tss2/tssprint.h>
#include <tss2/tsstransmit.h>
#include <tss2/Unmarshal_fp.h>
#include <tss2/tssresponsecode.h>
#include <tss2/tsscrypto.h>
#include <tss2/tsscryptoh.h>
#include <pbc.h>
#include <pbc_test.h>
#include <openssl/sha.h>

TPM_RC initTPM(void);
TPM_RC createMemKeyP1(
			unsigned char *I_x,
			unsigned char *I_y,
			double *time_taken
		   );
TPM_RC createMemKeyP2(
			unsigned char *h1_x,
			unsigned char *h1_y,
			unsigned char *Rm_x,
			unsigned char *Rm_y,
			uint16_t *cntr,
			double *time_taken
		   );
TPM_RC createMemKeyP3(
			uint16_t cntr,
			uint32_t nonce,
			unsigned char *chm,
			unsigned char *ctm,
			unsigned char *sfm,
			double *time_taken
		   );
TPM_RC getSignKeyP1(
			unsigned char *h1_x,
			unsigned char *h1_y,
			unsigned char *bj,
			unsigned char *d2j,
			unsigned char *Ej_x,
			unsigned char *Ej_y,
			unsigned char *S10_x,
			unsigned char *S10_y,
			unsigned char *S20_x,
			unsigned char *S20_y,
			uint16_t *cntr,
			double *time_taken
		   );
TPM_RC getSignKeyP2(
			uint16_t cntr,
			uint32_t nonce, // how to gen on TPM??
			unsigned char *ch0,
			unsigned char *cg0,
			unsigned char *sfg,
			double *time_taken
		   );
TPM_RC getSignKeyP3(
			unsigned char *Dj_x,
			unsigned char *Dj_y,
			unsigned char *bi,
			unsigned char *d2i,
			unsigned char *Oi_x,
			unsigned char *Oi_y,
			unsigned char *S1i_x,
			unsigned char *S1i_y,
			unsigned char *S2i_x,
			unsigned char *S2i_y,
			uint16_t *cntr,
			double *time_taken
		   );
TPM_RC getSignKeyP4(
			uint16_t cntr,
			uint32_t nonce,
			unsigned char *chi,
			unsigned char *cgi,
			unsigned char *sfi,
			double *time_taken
		   );
TPM_RC signP1(
			unsigned char *h1_x,
			unsigned char *h1_y,
			unsigned char *xjk,
			unsigned char *d2,
			unsigned char *E_x,
			unsigned char *E_y,
			unsigned char *S1s_x,
			unsigned char *S1s_y,
			unsigned char *S2s_x,
			unsigned char *S2s_y,
			uint16_t *cntr,
			double *time_taken
	     );
TPM_RC signP2(
			uint16_t cntr,
			uint32_t nonce,
			unsigned char *chs,
			char *M,
			uint32_t M_len,
			unsigned char *sfs,
			unsigned char *cts,
			double *time_taken
	     );
TPM_RC commit_helper(
			unsigned char *P1_x, 
			unsigned char *P1_y,
			unsigned char *s2,
			unsigned char *y2,
			unsigned char *K_x,
			unsigned char *K_y,
			unsigned char *L_x,
			unsigned char *L_y,
			unsigned char *E_x,
			unsigned char *E_y,
			uint16_t *cntr,
			double *time_taken
		    );
TPM_RC sign_helper(
			uint16_t cntr,
			uint32_t nonce,
			unsigned char *hash,
			char *msg,
			uint32_t msg_len,
			unsigned char *r,
			unsigned char *s,
			double *time_taken
		  );
