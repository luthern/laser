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
TPM_RC joinP1(
			unsigned char *I_x,
			unsigned char *I_y,
			double *time_taken
		   );
TPM_RC joinP2(
			unsigned char *h1_x,
			unsigned char *h1_y,
			unsigned char *Rm_x,
			unsigned char *Rm_y,
			uint16_t *cntr,
			double *time_taken
		   );
TPM_RC joinP3(
			uint16_t cntr,
			uint32_t nm,
			unsigned char *chm,
			uint32_t *ntm,
			unsigned char *ctm,
			unsigned char *sfm,
			double *time_taken
		   );
TPM_RC getSignCreP1(
			unsigned char *h1_x,
			unsigned char *h1_y,
			unsigned char *a10,
			unsigned char *b20,
			unsigned char *K0_x,
			unsigned char *K0_y,
			unsigned char *S10_x,
			unsigned char *S10_y,
			unsigned char *S20_x,
			unsigned char *S20_y,
			uint16_t *cntr,
			double *time_taken
		   );
TPM_RC getSignCreP2(
			uint16_t cntr,
			uint32_t ng,
			unsigned char *ch0,
			uint32_t *nt0,
			unsigned char *ct0,
			unsigned char *sf0,
			double *time_taken
		   );
TPM_RC getSignCreP3(
			unsigned char *B0_x,
			unsigned char *B0_y,
			unsigned char *a1i,
			unsigned char *b2i,
			unsigned char *Oi_x,
			unsigned char *Oi_y,
			unsigned char *S1i_x,
			unsigned char *S1i_y,
			unsigned char *S2i_x,
			unsigned char *S2i_y,
			uint16_t *cntr,
			double *time_taken
		   );
TPM_RC getSignCreP4(
			uint16_t cntr,
			uint32_t ng,
			unsigned char *chi,
			uint32_t *nti,
			unsigned char *cti,
			unsigned char *sfi,
			double *time_taken
		   );
TPM_RC signP1(
			unsigned char *h1_x,
			unsigned char *h1_y,
			unsigned char *a1s,
			unsigned char *b2s,
			unsigned char *Ks_x,
			unsigned char *Ks_y,
			unsigned char *S1s_x,
			unsigned char *S1s_y,
			unsigned char *S2s_x,
			unsigned char *S2s_y,
			uint16_t *cntr,
			double *time_taken
	     );
TPM_RC signP2(
			uint16_t cntr,
			unsigned char *chs,
			char *M,
			uint32_t M_len,
			uint32_t *nts,
			unsigned char *cts,
			unsigned char *sfs,
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
			uint32_t *nonce_gen,
			unsigned char *r,
			unsigned char *s,
			double *time_taken
		  );
TPM_RC getRandomNonce(uint32_t *nonce);
TPM_RC flush_handles(void);
