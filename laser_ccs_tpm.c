#include "laser.h"
#include "laser_tpm.h"

uint64_t aliasTokensPerSignCre = 5, baseRL_entries = 5;
double t0 = 0, t1 = 0, tpm = 0, host = 0, iss = 0;
static pairing_t pairing;
static FILE *fp;

void Hash1(element_t z1, element_t z2, element_t z)
{
	memset(ibuf, 0, sizeof ibuf);
	memset(jbuf, 0, sizeof jbuf);
	element_to_bytes(jbuf, z1);
	element_to_bytes(jbuf, z2);
	memcpy(ibuf + l1, jbuf, l1);
	SHA256(ibuf, 2 * l1, obuf);
	element_from_hash(z, obuf, 32);
}

void setPoint(element_t B0, element_t a1j)
{
	curve_data_ptr cdp = B0->field->data;
	point_ptr pt = B0->data;
	element_t t;
	element_init(t, cdp->field);
	pt->inf_flag = 0;

	do {
		element_random(a1j);
		memset(jbuf, 0, sizeof jbuf);
		element_to_bytes(jbuf, a1j);
		SHA256(jbuf, 32, obuf);
		element_from_hash(pt->x, obuf, 32);

		element_square(t, pt->x);
		element_add(t, t, cdp->a);
		element_mul(t, t, pt->x);
		element_add(t, t, cdp->b);
	} while (!element_is_sqr(t));
	element_sqrt(pt->y, t);
	element_clear(t);
}

void Hash2(element_t z, element_t B, element_t K, element_t L, element_t Uo,
	   element_t Ut, element_t Ue, element_t Ro, element_t Rt, element_t Re,
	   element_t Rf, int q)
{
	memset(ibuf, 0, sizeof ibuf);
	memset(jbuf, 0, sizeof jbuf);
	element_to_bytes(ibuf, B);
	element_to_bytes(jbuf, K);
	memcpy(ibuf + l1, jbuf, l1);
	element_to_bytes(jbuf, L);
	memcpy(ibuf + 2 * l1, jbuf, l1);
	element_to_bytes(jbuf, Uo);
	memcpy(ibuf + 3 * l1, jbuf, l1);
	element_to_bytes(jbuf, Ut);
	memcpy(ibuf + 4 * l1, jbuf, l1);
	element_to_bytes(jbuf, Ue);
	memcpy(ibuf + 5 * l1, jbuf, l1);
	element_to_bytes(jbuf, Ro);
	memcpy(ibuf + 6 * l1, jbuf, l1);

	if (q > 7) {
		element_to_bytes(jbuf, Rt);
		memcpy(ibuf + 7 * l1, jbuf, l1);
		element_to_bytes(jbuf, Re);
		memcpy(ibuf + 8 * l1, jbuf, l1);
	}
	if (q > 8) {
		element_to_bytes(jbuf, Rf);
		memcpy(ibuf + 9 * l1, jbuf, l1);
	}

	SHA256(ibuf, strlen((char *)ibuf), obuf);
	element_from_hash(z, obuf, 32);
}

int setupLaser(element_t issuerSecret, struct groupPublicKey *gpk)
{
	element_random(issuerSecret);

	element_init_G1(gpk->g1, pairing);
	element_init_G2(gpk->g2, pairing);
	element_init_G1(gpk->h1, pairing);
	element_init_G1(gpk->h2, pairing);
	element_init_G1(gpk->h3, pairing);
	element_init_G2(gpk->omega, pairing);

	// initialize gpk entries
	element_random(gpk->g1);
	element_random(gpk->g2);

	unsigned char h1x[32] = {0x00};
	unsigned char h1y[32] = {0x00};
	unsigned char h1_buf[64];
	h1x[31] = 0x01;
	h1y[31] = 0x02;
	memcpy(h1_buf, h1x, 32);
	memcpy(h1_buf + 32, h1y, 32);

	element_from_bytes_compressed(gpk->h1, h1_buf);
	element_random(gpk->h2);
	element_random(gpk->h3);
	element_pow_zn(gpk->omega, gpk->g2, issuerSecret);
	return 0;
}

TPM_RC joinHost(struct groupPublicKey * const gpk, uint32_t nm, 
		element_t pubTPM, uint32_t *ntm, element_t ctm,
		element_t sfm)
{
	TPM_RC rc = 0;
	element_t Rm;
	element_t chm;
	element_init_G1(Rm, pairing);
	element_init_Zr(chm, pairing);
	
	/* createMemKeyP1 */
	double *time_taken = malloc(sizeof(double));
	unsigned char I_x[32];
	unsigned char I_y[32];
	rc = createMemKeyP1(I_x, I_y, time_taken);
	if (rc != 0)
	{
		perror("createMemKeyP1 failed");
		element_clear(Rm);
		element_clear(chm);
		free(time_taken);
		return rc;
	}
	unsigned char I_buf[64];
	memcpy(I_buf, I_x, 32);
	memcpy(I_buf + 32, I_y, 32);
	
	// output pubTPM
	element_from_bytes(pubTPM, I_buf);	
	tpm += *time_taken;

	/* createMemKeyP2 */

	/* TPM is supposed to create this nonce... :( */
	// output ntm
	int err = fread(ntm, 4, 1, fp);
	if (err != 1) {
		perror("read urandom failed");
		element_clear(Rm);
		element_clear(chm);
		free(time_taken);
		return TPM_RC_NO_RESULT;
	}	

	uint16_t *commit_cntr = malloc(sizeof(uint16_t));

	unsigned char pt_buf[64];
	element_to_bytes(pt_buf, gpk->h1);
	unsigned char Rm_buf[64];

	rc = createMemKeyP2(pt_buf, pt_buf + 32, Rm_buf, Rm_buf + 32, commit_cntr, time_taken);
	if (rc != 0)
	{
		perror("createMemKeyP2 failed");
		element_clear(Rm);
		element_clear(chm);
		free(time_taken);
		free(commit_cntr);
		return rc;
	}
	element_from_bytes(Rm, Rm_buf);
	tpm += *time_taken;

	/* createMemKeyP3 4(b) */
	Hash1(pubTPM, Rm, chm);
	/* createMemKeyP3 */

	unsigned char ctm_buf[32];
	unsigned char chm_buf[32];
	unsigned char sfm_buf[32];

	element_to_bytes(chm_buf, chm);
	// NEED TO HASH nm into chm <-- Pranav is working on this. 
	rc = createMemKeyP3(*commit_cntr, *ntm, chm_buf, ctm_buf, sfm_buf, time_taken);
	if (rc != 0) 
	{
		perror("createMemKeyP3 failed");
		element_clear(Rm);
		element_clear(chm);
		free(time_taken);
		free(commit_cntr);
		return rc;
	}		
	// output ctm, sfm
	element_from_bytes(ctm, ctm_buf);
	element_from_bytes(sfm, sfm_buf);
	tpm += *time_taken;
	
	free(time_taken);
	free(commit_cntr);
	element_clear(Rm);
	element_clear(chm);
	return 0;
}

int joinIssuer(struct groupPublicKey * const gpk, element_t issuerSecret, uint32_t nm,
		element_t pubTPM, uint32_t ntm, element_t ctm, element_t sfm,
		struct membershipCredential * memCre)
{
	element_t chm_hat;
	element_t Rm_hat;
	element_t ctm_hat;
	element_t temp;
	element_init_Zr(temp, pairing);
	element_init_G1(Rm_hat, pairing);
	element_init_Zr(chm_hat, pairing);
	element_init_Zr(ctm_hat, pairing);

	unsigned char buffer[36];
	unsigned char hashout[32];

	element_neg(temp, ctm);
	element_pow2_zn(Rm_hat, gpk->h1, sfm, pubTPM, temp);
	Hash1(pubTPM, Rm_hat, chm_hat);	
	element_clear(temp);
	
	element_to_bytes(buffer, chm_hat);
	memcpy(buffer + 32, &ntm, sizeof(uint32_t));
	SHA256(buffer, 36, hashout);
	element_from_hash(ctm_hat, hashout, 32);

	// TODO: Terminate on first failure and clean up all resources 
	if (element_cmp(ctm_hat, ctm))
		printf("GetMemKey 5(b) verification not passed! :( \n");
	else 
		printf("5(b) verified\n");

	/* Clean up temporary variables */
	element_clear(Rm_hat);
	element_clear(chm_hat);
	element_clear(ctm_hat);

	/* Setup memCre */
	element_init_G1(memCre->J, pairing);
	element_init_Zr(memCre->t, pairing);
	element_init_Zr(memCre->d, pairing);
	element_random(memCre->t);
	element_random(memCre->d);

	element_t tempG1;
	element_t exponent;
	element_init_Zr(exponent, pairing);
	element_init_G1(tempG1, pairing);

	element_add(exponent, issuerSecret, memCre->t);
	element_invert(exponent, exponent);
	element_pow_zn(tempG1, gpk->h2, memCre->d);
	element_mul(tempG1, pubTPM, tempG1);
	element_mul(tempG1, gpk->g1, tempG1);
	element_pow_zn(memCre->J, tempG1, exponent);
	/* Clean up temporary variables */
	element_clear(exponent);

	return 0;
}

int initSignatureSigma0(struct membershipProof *sigma0)
{
	int err = fread(&sigma0->nt0, 4, 1, fp);
	if (err != 1) {
		perror("read urandom failed");
		return -1;
	}
	element_init_Zr(sigma0->a10, pairing);
	element_init_Zr(sigma0->b20, pairing);	
	element_init_G1(sigma0->K0, pairing);
	element_init_G1(sigma0->L, pairing);
	element_init_G1(sigma0->U1, pairing);
	element_init_G1(sigma0->U2, pairing);
	element_init_G1(sigma0->U3, pairing);
	element_init_Zr(sigma0->ct0, pairing);
	element_init_Zr(sigma0->sf0, pairing);
	element_init_Zr(sigma0->sy, pairing);
	element_init_Zr(sigma0->st, pairing);
	element_init_Zr(sigma0->stheta, pairing);
	element_init_Zr(sigma0->sxi, pairing);
	element_init_Zr(sigma0->snu, pairing);
	return 0;
}

int proveMembership(element_t pubTPM, struct groupPublicKey *gpk,
		struct membershipCredential *memCre, uint32_t ng, 
		element_t yj, struct membershipProof *sigma0)
{
	TPM_RC rc = 0;

	/* Initialize membershipProof struct */
	int err = initSignatureSigma0(sigma0);
	if (err != 0) 
	{
		perror("error in sigma0 initialization");
		return err;
	}
	
	/* In the scheme, we select a00 unif. at random from Zp 
	 * and then compute (a10, b10, b20) = Hg(a00)
	 * Here instead we compute B0 = (b10, b20) and a10 with setPoint
	 * This is a limitation of the TPM specification. 
	 */
	element_t B0;
	element_init_G1(B0, pairing);

	//SetPoint 'B0', a10 is the preimage of B0->x
	setPoint(B0, sigma0->a10);
	
	/* Copy B0->y into sigma0->b20 */
	unsigned char b20_buf[32];
	element_to_bytes(b20_buf, element_y(B0));
	element_from_bytes(sigma0->b20, b20_buf);

	unsigned char pt_buf[64];
	element_to_bytes(pt_buf, gpk->h1);

	unsigned char a10_buf[32];
	element_to_bytes(a10_buf, sigma0->a10);

	unsigned char K0_buf[64];
	unsigned char S10_buf[64];
	unsigned char S20_buf[64];

	double *time_taken = malloc(sizeof(double));
	uint16_t *commit_cntr = malloc(sizeof(uint16_t));

	rc = getSignKeyP1(pt_buf, pt_buf + 32, a10_buf, b20_buf,
			K0_buf, K0_buf + 32, S10_buf, S10_buf + 32, 
			S20_buf, S20_buf + 32, commit_cntr, time_taken);
	if (rc != 0)
	{
		perror("getSignKeyP1 failed");
		exit(1);
	} else
		printf("getSignKeyP1 complete\n");
	
	element_from_bytes(sigma0->K0, K0_buf);
	element_printf("%B\n", sigma0->K0);
	element_t S10;
	element_t S20;
	element_init_G1(S10, pairing);
	element_init_G1(S20, pairing);
	element_from_bytes(S10, S10_buf);
	element_from_bytes(S20, S20_buf);

	/* (3)(c) Note that yj is needed by platform in (9)*/
	element_init_Zr(yj, pairing);
	element_random(yj);
	
	element_t theta, xi;
	element_init_Zr(theta, pairing);
	element_init_Zr(xi, pairing);
  	element_random(theta);
  	element_random(xi);

	/* Compute nu */
	element_t nu;
	element_init_Zr(nu, pairing);
  	element_mul(nu, theta, xi);
  	element_add(nu, nu, memCre->d);

	/* Compute sigma0->L, allocate an element_t to serve as const 1 */
	element_t one;
	element_init_Zr(one, pairing);
	element_set1(one);
	element_pow2_zn(sigma0->L, pubTPM, one, gpk->h2, yj);
	
	/* Compute hm */
	element_t hm;
	element_init_G1(hm, pairing);
	element_pow3_zn(hm, gpk->g1, one, pubTPM, one, gpk->h2, memCre->d);

	/* Compute sigma0->U1, sigma0->U2, sigma0->U3 */
	element_t theta_inv;
	element_init_Zr(theta_inv, pairing);
	element_invert(theta_inv, theta);

	element_t neg_t;
	element_init_Zr(neg_t, pairing);
  	element_neg(neg_t, memCre->t);

	element_pow_zn(sigma0->U1, memCre->J, theta_inv);
	element_pow2_zn(sigma0->U2, memCre->J, neg_t, hm, one);
  	element_pow_zn(sigma0->U2, sigma0->U2, theta_inv);
  	element_pow2_zn(sigma0->U3, hm, theta_inv, gpk->h2, xi);
	
	/* Clear variables storing inverse theta and negative t */
	element_clear(theta_inv);
	element_clear(neg_t);

	/* (3)(d) select random variables */
	element_t ry, rt, rtheta, rxi, rnu;
  	element_init_Zr(ry, pairing);
  	element_init_Zr(rt, pairing);
  	element_init_Zr(rtheta, pairing);
  	element_init_Zr(rxi, pairing);
  	element_init_Zr(rnu, pairing);
  	element_random(ry);
  	element_random(rt);
  	element_random(rtheta);
  	element_random(rxi);
  	element_random(rnu);

	/* (3)(d) compute R10, R20, R30, R40 */
	element_t R10, R20, R30, R40;
	element_init_G1(R10, pairing);
	element_init_G1(R20, pairing);
	element_init_G1(R30, pairing);
	element_init_G1(R40, pairing);
 	
	element_t neg_rnu, S20_inv;
	element_init_Zr(neg_rnu, pairing);
	element_init_G1(S20_inv, pairing);
	element_neg(neg_rnu, rnu);
  	element_invert(S20_inv, S20);
  	
	element_mul(R10, S10, one);	
	element_pow2_zn(R20, S20, one, gpk->h2, ry);
	element_pow2_zn(R30, sigma0->U1, rt, gpk->h2, rxi);
	element_pow3_zn(R40, sigma0->U3, rtheta, S20_inv, one, gpk->h2, neg_rnu);

	element_clear(neg_rnu);
	element_clear(S20_inv);
	element_clear(S10);
	element_clear(S20);

	/* Compute ch0 via Hash2 function */
	element_t ch0;
	element_init_Zr(ch0, pairing);
  	Hash2(ch0, B0, sigma0->K0, sigma0->L, sigma0->U1, sigma0->U2, 
			sigma0->U3, R10, R20, R30, R40, 9);
	// TODO: Add in nt0 to the hash here ?? 

	/* TPM getSignKeyP2 */
	unsigned char ct0_buf[32];
	unsigned char sf0_buf[32];
	unsigned char ch0_buf[32];
	element_to_bytes(ch0_buf, ch0);

	rc = getSignKeyP2(*commit_cntr, ng, ch0_buf, 
			ct0_buf, sf0_buf, time_taken);
	if (rc != 0) {
		perror("getSignKeyP2 failed");
		exit(1);
	}
	else
		printf("getSignKeyP2 complete\n");
	free(commit_cntr);
	free(time_taken);

	element_from_bytes(sigma0->ct0, ct0_buf);
	element_from_bytes(sigma0->sf0, sf0_buf);
	/* TODO: Set nonce by generation on TPM. 
	 * Currently set by the initializer to random val
	 */
	
	element_mul(sigma0->sy, sigma0->ct0, yj);
	element_add(sigma0->sy, ry, sigma0->sy);
	element_mul(sigma0->st, sigma0->ct0, memCre->t);
	element_add(sigma0->st, rt, sigma0->st);
	element_mul(sigma0->stheta, sigma0->ct0, theta);
	element_add(sigma0->stheta, rtheta, sigma0->stheta);
	element_mul(sigma0->sxi, sigma0->ct0, xi);
	element_add(sigma0->sxi, rxi, sigma0->sxi);
	element_mul(sigma0->snu, sigma0->ct0, nu);
	element_add(sigma0->snu, rnu, sigma0->snu);

	/* We've now constructed the whole signature sigma0
	 * Clean up the remaining unneeded variables
	 * Our output is sigma0, yj
	 */

	element_clear(B0);
	element_clear(theta);
	element_clear(xi);
	element_clear(nu);
	element_clear(hm);
	element_clear(one);
	element_clear(ry);
	element_clear(rt);
	element_clear(rtheta);
	element_clear(rxi);
	element_clear(rnu);
	element_clear(R10);
	element_clear(R20);
	element_clear(R30);
	element_clear(R40);
	element_clear(ch0);
	return 0;
}

void addRandomRevocationListEntry(struct basenameRevocationList *baseRL)
{
	if (baseRL->entries == 0) {
		baseRL->revokedBasenameList = 
			malloc(sizeof(struct revocationListEntry *));
	} else {
		/* Extend list */
		baseRL->revokedBasenameList = 
			realloc(baseRL->revokedBasenameList, 
			(baseRL->entries + 1) 
			* sizeof(struct revocationListEntry *));
	}

	/* Generate an entry for the revokedBasenameList */
	baseRL->revokedBasenameList[baseRL->entries] = 
		malloc(sizeof(struct revocationListEntry));
	element_init_Zr(baseRL->revokedBasenameList[baseRL->entries]->a1i, pairing);
	element_init_Zr(baseRL->revokedBasenameList[baseRL->entries]->b2i, pairing);
	element_init_G1(baseRL->revokedBasenameList[baseRL->entries]->Ki, pairing);

	/* Choose the values for the revocation list entry randomly */
	element_t Bi;
	element_init_G1(Bi, pairing);
	setPoint(Bi, baseRL->revokedBasenameList[baseRL->entries]->a1i);
	unsigned char b2i_buf[32];
	element_to_bytes(b2i_buf, element_y(Bi));
	element_from_bytes(baseRL->revokedBasenameList[baseRL->entries]->b2i, b2i_buf);
	
	element_t randomKey;
	element_init_Zr(randomKey, pairing);
	element_random(randomKey);
	element_pow_zn(baseRL->revokedBasenameList[baseRL->entries]->Ki, Bi, randomKey);

	element_clear(randomKey);
	element_clear(Bi);
	/* Increment entries in the list */	
	baseRL->entries += 1;
}

/*
 * We assert that the length of the revocation list will be extended when 
 * a new entry is added to support arbitrary length lists.
 */
void generateBaseRL(int numRevoked, struct basenameRevocationList *baseRL) 
{
	/* baseRL must be allocated memory, but not yet filled */
	baseRL->entries = 0;

	int i;
	for (i = 0; i < numRevoked; i++) {
		addRandomRevocationListEntry(baseRL);
	}
	printf("Entries in revocation list: %d\n", baseRL->entries);
}

int singleBasenameProof(int index, uint32_t ng,
	       	struct revocationListEntry *revEntry, struct sigmaG *sigmaG)
{
	sigmaG->proofsOfNonRevocation[index] = malloc(sizeof(struct basenameProof));
	struct basenameProof *proof = sigmaG->proofsOfNonRevocation[index];
	element_init_G1(proof->Pi, pairing);
	element_init_Zr(proof->cti, pairing);
	element_init_Zr(proof->staui, pairing);
	element_init_Zr(proof->svi, pairing);
	
	/* nti supposed to be TPM generated, is not */
	int err = fread(&proof->nti, 4, 1, fp);
	if (err != 1) {
		perror("read urandom failed");
		return err;
	}	

	unsigned char a1i_buf[32];
	unsigned char Bi_buf[64];
	element_to_bytes(a1i_buf, revEntry->a1i);
	SHA256(a1i_buf, 32, Bi_buf);
	element_to_bytes(Bi_buf + 32, revEntry->b2i);

	element_t Bi;
	element_init_G1(Bi, pairing);
	element_from_bytes(Bi, Bi_buf);

	/* Reproduce B0 from proofMembership */
	unsigned char B0_buf[64];
	unsigned char a10_buf[32];
	element_to_bytes(a10_buf, sigmaG->sigma0->a10);
	SHA256(a10_buf, 32, B0_buf);
	element_to_bytes(B0_buf + 32, sigmaG->sigma0->b20);		
	element_t B0;
	element_init_G1(B0, pairing);
	element_from_bytes(B0, B0_buf);
	
	/* Next up TPM things */

	uint16_t *commit_cntr = malloc(sizeof(uint16_t));
	double *time_taken = malloc(sizeof(double));

	unsigned char Oi_buf[64];
	unsigned char S1i_buf[64];
	unsigned char S2i_buf[64];	
	err = getSignKeyP3(B0_buf, B0_buf + 32, a1i_buf, Bi_buf + 32,
			Oi_buf, Oi_buf + 32, S1i_buf, S1i_buf + 32, S2i_buf, S2i_buf + 32,
			commit_cntr, time_taken);
	if (err != 0) {
		perror("getSignKeyP3 failed");
		return err;
	} else
		printf("getSignKeyP3 complete\n");
	
	element_t Oi, S1i, S2i;
	element_init_G1(Oi, pairing);
	element_init_G1(S1i, pairing);
	element_init_G1(S2i, pairing);
	element_from_bytes(Oi, Oi_buf);
	element_from_bytes(S1i, S1i_buf);
	element_from_bytes(S2i, S2i_buf);

	// GetSignCre (4)(c) verification Ki =/= Oi.
	
	if (!element_cmp(revEntry->Ki, Oi)) {
		printf("GetSignCre (4)(c) verification not passed!\n");
	} else {
		printf("GetSignCre (4)(c) passed\n");
	}

	element_t taui;
	element_t rtaui;
	element_init_Zr(taui, pairing);
	element_init_Zr(rtaui, pairing);
	element_random(taui);
	element_random(rtaui);

	// Compute proof->Pi
	element_invert(proof->Pi, revEntry->Ki);
	element_mul(proof->Pi, proof->Pi, Oi);
	element_pow_zn(proof->Pi, proof->Pi, taui);
	element_clear(Oi);
	
	// Compute R1i, R2i
	element_t R1i, R2i;
	element_init_G1(R1i, pairing);
	element_init_G1(R2i, pairing);
	element_t neg_rtaui;
	element_init_Zr(neg_rtaui, pairing);
	element_neg(neg_rtaui, rtaui);
	element_pow2_zn(R1i, S1i, taui, revEntry->Ki, neg_rtaui);
	element_pow2_zn(R2i, S2i, taui, sigmaG->sigma0->K0, neg_rtaui);
	element_clear(neg_rtaui);
	element_clear(S1i);
	element_clear(S2i);
	
	element_t chi;
	element_init_Zr(chi, pairing);

	Hash2(chi, B0, sigmaG->sigma0->K0, Bi, revEntry->Ki, proof->Pi, R1i, R2i, NULL,
			NULL, NULL, 6);
	element_clear(R1i);
	element_clear(R2i);
	element_clear(Bi);
	element_clear(B0);
	
	unsigned char chi_buf[32];
	element_to_bytes(chi_buf, chi);
	unsigned char cti_buf[32];
	unsigned char sfi_buf[32];

	err = getSignKeyP4(*commit_cntr, ng, chi_buf, cti_buf, sfi_buf, time_taken);
	if (err != 0) {
		perror("getSignKeyP4 failed");
		element_clear(taui);
		element_clear(rtaui);
		free(commit_cntr);
		return -1;
	} else
		printf("getSignKeyP4 complete\n");
	free(commit_cntr);
	element_clear(chi);
	element_from_bytes(proof->cti, cti_buf);
	
	element_t sfi;
	element_init_Zr(sfi, pairing);
	element_from_bytes(sfi, sfi_buf);

	element_mul(proof->staui, proof->cti, taui);
	element_add(proof->staui, proof->staui, rtaui);
	
	element_mul(proof->svi, taui, sfi);
	
	element_clear(sfi);
	element_clear(taui);
	element_clear(rtaui);
	return 0;
}	

int proveUnrevokedBasename(struct basenameRevocationList *baseRL, 
		uint32_t ng, struct sigmaG *sig)
{
	int i;
	int err;
	
	sig->entries = baseRL->entries;
	sig->proofsOfNonRevocation = 
		malloc(sig->entries * sizeof(struct basenameProof *));
	
	for (i = 0; i < baseRL->entries; i++)
	{
		err = singleBasenameProof(i, ng, baseRL->revokedBasenameList[i], sig);
		if (err != 0) {
			perror("My basename was revoked!!");
			return err;
		}
	}
	return 0;
}

int issuerValidateMembership(struct membershipProof *sigma0, 
		struct groupPublicKey *gpk, uint32_t ng)
{
	element_t pairing_U1_omega, pairing_U2_g2;
	element_init_GT(pairing_U1_omega, pairing);
	element_init_GT(pairing_U2_g2, pairing);
	element_pairing(pairing_U1_omega, sigma0->U1, gpk->omega);
	element_pairing(pairing_U2_g2, sigma0->U2, gpk->g2);

	/* Compare returns 0 if they are the same entity */
	if (element_cmp(pairing_U1_omega, pairing_U2_g2)) {
		printf("Issuer verification of membership (6)(a) not passed\n");
		element_clear(pairing_U1_omega);
		element_clear(pairing_U2_g2);
		return 1;
	} else {
		printf("Issuer verification of membership (6)(a) passed\n");
	}
	
	element_clear(pairing_U1_omega);
	element_clear(pairing_U2_g2);

	unsigned char B0_buf[64];
	unsigned char a10_buf[32];
	element_to_bytes(a10_buf, sigma0->a10);
	SHA256(a10_buf, 32, B0_buf);
	element_to_bytes(B0_buf + 32, sigma0->b20);		
	element_t B0;
	element_init_G1(B0, pairing);
	element_from_bytes(B0, B0_buf);

	element_t R10_hat, R20_hat, R30_hat, R40_hat;
	element_init_G1(R10_hat, pairing);
	element_init_G1(R20_hat, pairing);
	element_init_G1(R30_hat, pairing);
	element_init_G1(R40_hat, pairing);

	element_t neg_ct0;
	element_init_Zr(neg_ct0, pairing);
	element_neg(neg_ct0, sigma0->ct0);
	
	element_t one;
	element_init_Zr(one, pairing);
	element_set1(one);
	
	element_pow2_zn(R10_hat, B0, sigma0->sf0, sigma0->K0, neg_ct0);
	element_pow3_zn(R20_hat, gpk->h1, sigma0->sf0, 
			gpk->h2, sigma0->sy, sigma0->L, neg_ct0);
	element_pow2_zn(R30_hat, sigma0->U2, sigma0->ct0, sigma0->U3, neg_ct0);
	element_pow3_zn(R30_hat, sigma0->U1, sigma0->st, 
			gpk->h2, sigma0->sxi, R30_hat, one);
	
	element_t neg_sf0;
	element_t neg_snu;
	element_init_Zr(neg_sf0, pairing);
	element_init_Zr(neg_snu, pairing);
	element_neg(neg_sf0, sigma0->sf0);
	element_neg(neg_snu, sigma0->snu);

	element_pow2_zn(R40_hat, gpk->h2, neg_snu, gpk->g1, neg_ct0);
	element_pow3_zn(R40_hat, sigma0->U3, sigma0->stheta, 
			gpk->h1, neg_sf0, R40_hat, one);

	element_clear(one);
	element_clear(neg_ct0);
	element_clear(neg_sf0);
	element_clear(neg_snu);

	element_t ch0_hat;
	element_init_Zr(ch0_hat, pairing);

	Hash2(ch0_hat, B0, sigma0->K0, sigma0->L, sigma0->U1, sigma0->U2, sigma0->U3, 
			R10_hat, R20_hat, R30_hat, R40_hat, 9);

	element_clear(R10_hat);
	element_clear(R20_hat);
	element_clear(R30_hat);
	element_clear(R40_hat);
	element_clear(B0);
	
	unsigned char hash_buf[32 + (2 * sizeof(uint32_t))];
	unsigned char ct0_hat_buf[32];
	element_to_bytes(hash_buf, ch0_hat);
	// TODO: Fix it so nonces make sense
	// memcpy(hash_buf + 32, &sigma0->nt0, sizeof(uint32_t));
	memcpy(hash_buf + 32 /*+ sizeof(uint32_t)*/, &ng, sizeof(uint32_t));
	SHA256(hash_buf, 32 + (/*2 **/ sizeof(uint32_t)), ct0_hat_buf);
	element_t ct0_hat;
	element_init_Zr(ct0_hat, pairing);
	element_from_hash(ct0_hat, ct0_hat_buf, 32);

	if (element_cmp(ct0_hat, sigma0->ct0)) {
		printf("GetSignKey Issuer Membership Verification (6)(d) not passed!\n");
		element_clear(ct0_hat);
		element_clear(ch0_hat);
		return 1;
	} else {
		printf("GetSignKey Issuer Membership Verification (6)(d) passed!\n");
	}
	element_clear(ct0_hat);
	element_clear(ch0_hat);
	return 0;
}

int issuerValidateSingleRevProof(struct revocationListEntry *entry,
		struct basenameProof *baseProof, 
		struct membershipProof *sigma0, 
		uint32_t ng)
{
	/* Reproduce Bi from the revocation list entry */
	unsigned char Bi_buf[64];
	unsigned char a1i_buf[32];
	element_to_bytes(a1i_buf, entry->a1i);
	SHA256(a1i_buf, 32, Bi_buf);
	element_to_bytes(Bi_buf + 32, entry->b2i);		
	element_t Bi;
	element_init_G1(Bi, pairing);
	element_from_bytes(Bi, Bi_buf);

	element_t R1i_hat, R2i_hat;
	element_init_G1(R1i_hat, pairing);
	element_init_G1(R2i_hat, pairing);
	
	element_t neg_staui;
	element_t neg_cti;
	element_init_Zr(neg_staui, pairing);
	element_init_Zr(neg_cti, pairing);
	element_neg(neg_staui, baseProof->staui);
	element_neg(neg_cti, baseProof->cti);
	
	element_pow3_zn(R1i_hat, Bi, baseProof->svi, entry->Ki, neg_staui, 
			baseProof->Pi, neg_cti);
	
	/* Reproduce B0 for R2i_hat.. TODO: pass this instead of constantly
	 * regenerating it from the values in the signature even in the same
	 * entities' context (i.e., issuer generates once and then uses in
	 * all subfunctions that need it during validation of signCredential req.
	 */
	unsigned char B0_buf[64];
	unsigned char a10_buf[32];
	element_to_bytes(a10_buf, sigma0->a10);
	SHA256(a10_buf, 32, B0_buf);
	element_to_bytes(B0_buf + 32, sigma0->b20);		
	element_t B0;
	element_init_G1(B0, pairing);
	element_from_bytes(B0, B0_buf);

	element_pow2_zn(R2i_hat, B0, baseProof->svi, sigma0->K0, neg_staui);

	element_clear(neg_staui);
	element_clear(neg_cti);

	/* Compute hash */
	element_t chi_hat;
	element_init_Zr(chi_hat, pairing);
	
	Hash2(chi_hat, B0, sigma0->K0, Bi, entry->Ki, baseProof->Pi, 
			R1i_hat, R2i_hat, NULL, NULL, NULL, 6);

	element_clear(B0);
	element_clear(Bi);
	element_clear(R1i_hat);
	element_clear(R2i_hat);
	
	element_t cti_hat;
	element_init_Zr(cti_hat, pairing);
	
	/* Compute cti_hat = SHA256(chi_hat, nti, ng) except drop nti till we
	 * TODO: make nonce use make sense, incl. TPM generation...
	 */	
	unsigned char buffer[32 + sizeof(uint32_t)];
	unsigned char cti_hat_buf[32];
	element_to_bytes(buffer, chi_hat);
	memcpy(buffer + 32, &ng, sizeof(uint32_t));
	SHA256(buffer, 32 + sizeof(uint32_t), cti_hat_buf);
	element_from_bytes(cti_hat, cti_hat_buf);

	if (element_cmp(cti_hat, baseProof->cti)) {
		element_clear(cti_hat);
		printf("Issuer Validation of non-revocation failed (7)(c)\n");
		return 1;
	}
	element_clear(cti_hat);

	element_t one_G1;
	element_init_G1(one_G1, pairing);
	element_set1(one_G1);
	/* Cannot compare G1 element to Zr.... this won't work.
	 * Need a more reasonable way to validate Pi is not one.*/
	element_printf("Pi: %B\n", baseProof->Pi);
	if (!element_cmp(baseProof->Pi, one_G1)) {
		printf("Pi = 1_G1. Failed Issuer GetSignCre (7)(d)\n");
		element_clear(one_G1);
		return 1;
	}
	element_clear(one_G1);
	return 0;	
}

int issuerValidateUnrevoked(struct basenameRevocationList *baseRL,
		struct sigmaG *proof, uint32_t ng)
{
	int ret = 0;
	int i;
	for (i = 0; i < proof->entries; i++) {
		ret = issuerValidateSingleRevProof(baseRL->revokedBasenameList[i],
				proof->proofsOfNonRevocation[i], proof->sigma0, ng);
		if (ret)
			return ret;
	}
	return ret;
}

int issuerValidationGetSignCre(struct basenameRevocationList *baseRL,
		struct sigmaG *proof, struct groupPublicKey *gpk, uint32_t ng)
{
	int ret = 0;
	ret = issuerValidateMembership(proof->sigma0, gpk, ng);
	if (ret == 0)
		ret = issuerValidateUnrevoked(baseRL, proof, ng);
	return ret;
}

void issuerAliasTokenGeneration(struct groupPublicKey *gpk, element_t issuerSecret,
		struct sigmaG *proof, struct registry *reg, 
		struct signingCredential *signCre)
{
	signCre->entries = proof->entries;
	reg->registryEntries = malloc(sizeof(struct registryEntry *));
	reg->registryEntries[reg->entries] = malloc(sizeof(struct registryEntry));
	element_init_Zr(reg->registryEntries[reg->entries]->a10, pairing);
	element_init_Zr(reg->registryEntries[reg->entries]->b20, pairing);
	element_init_G1(reg->registryEntries[reg->entries]->K0, pairing);
	element_set(reg->registryEntries[reg->entries]->a10, proof->sigma0->a10);
	element_set(reg->registryEntries[reg->entries]->b20, proof->sigma0->b20);
	element_set(reg->registryEntries[reg->entries]->K0, proof->sigma0->K0);
	int i;
	// TODO: More flexible registry allocation of memory so we can add more tokens
	// and have more than one signCredential. This is not possible with current code.
	reg->registryEntries[reg->entries]->alias_tokens_xs = 
		malloc(aliasTokensPerSignCre * sizeof(element_t));
	for (i = 0; i < aliasTokensPerSignCre; i++) {
		element_t xjk;
		element_t zjk;
		element_init_Zr(xjk, pairing);
		element_init_Zr(zjk, pairing);
		
		element_t Ajk;
		element_init_G1(Ajk, pairing);
		
		element_t one;
		element_init_Zr(one, pairing);
		element_set1(one);

		element_pow3_zn(Ajk, gpk->g1, one, proof->sigma0->L, one, 
				gpk->h3, xjk);
		element_t exponent;
		element_init_Zr(exponent, pairing);
		element_add(exponent, issuerSecret, zjk);
		element_invert(exponent, exponent);
		element_pow_zn(Ajk, Ajk, exponent);

		signCre->aliasTokenList[i] = malloc(sizeof(struct aliasCredential));
		element_init_G1(signCre->aliasTokenList[i]->Ajk, pairing);
		element_init_Zr(signCre->aliasTokenList[i]->xjk, pairing);
		element_init_Zr(signCre->aliasTokenList[i]->zjk, pairing);
		element_set(signCre->aliasTokenList[i]->Ajk, Ajk);
		element_set(signCre->aliasTokenList[i]->xjk, xjk);
		element_set(signCre->aliasTokenList[i]->zjk, zjk);

		// segfault here memory for the registry x coords
		element_init_Zr(reg->registryEntries[reg->entries]->alias_tokens_xs[i], 
				pairing);
		element_set(reg->registryEntries[reg->entries]->alias_tokens_xs[i], 
				xjk);
		
		element_clear(xjk);
		element_clear(zjk);
		element_clear(Ajk);
		element_clear(one);
		element_clear(exponent);
	}	
	reg->entries += 1;
}

void platformFinishTokens(struct signingCredential *signCre, element_t yj)
{
	int i;
	for (i = 0; i < aliasTokensPerSignCre; i++) {
		element_init_Zr(signCre->aliasTokenList[i]->yj, pairing);
		element_set(signCre->aliasTokenList[i]->yj, yj);
	}
}

void clearKeyMaterial(element_t pubTPM, element_t issuerSecret, 
		struct groupPublicKey *gpk, struct membershipCredential * memCre)
{
	printf("Entered clearKeyMaterial\n");
	element_clear(pubTPM);
	element_clear(issuerSecret);
	element_clear(gpk->g1);
	element_clear(gpk->g2);
	element_clear(gpk->h1);
	element_clear(gpk->h2);
	element_clear(gpk->h3);
	element_clear(gpk->omega);
	free(gpk);
	gpk = NULL;
	element_clear(memCre->J);
	element_clear(memCre->t);
	element_clear(memCre->d);
	free(memCre);
	memCre = NULL;
	TPM_RC rc = flush_handles();
	if (rc != 0)
	{
		perror("flush_handles failed");
		exit(1);
	}
}

void freeBaseRL(struct basenameRevocationList *baseRL)
{
	int i;
	for (i = 0; i < baseRL->entries; i++) {
		element_clear(baseRL->revokedBasenameList[i]->a1i);
		element_clear(baseRL->revokedBasenameList[i]->b2i);
		element_clear(baseRL->revokedBasenameList[i]->Ki);
		free(baseRL->revokedBasenameList[i]);
		baseRL->revokedBasenameList[i] = NULL;
	}
	free(baseRL);
}

void freeProofForIssuer(struct sigmaG *proof)
{
	element_clear(proof->sigma0->a10);
	element_clear(proof->sigma0->b20);
	element_clear(proof->sigma0->K0);
	element_clear(proof->sigma0->L);
	element_clear(proof->sigma0->U1);
	element_clear(proof->sigma0->U2);
	element_clear(proof->sigma0->U3);
	element_clear(proof->sigma0->ct0);
	element_clear(proof->sigma0->sf0);
	element_clear(proof->sigma0->sy);
	element_clear(proof->sigma0->st);
	element_clear(proof->sigma0->stheta);
	element_clear(proof->sigma0->snu);
	free(proof->sigma0);
	proof->sigma0 = NULL;
	int i;
	for (i = 0; i < proof->entries; i++) {
		
		element_clear(proof->proofsOfNonRevocation[i]->Pi);
		element_clear(proof->proofsOfNonRevocation[i]->cti);
		element_clear(proof->proofsOfNonRevocation[i]->staui);
		element_clear(proof->proofsOfNonRevocation[i]->svi);
		free(proof->proofsOfNonRevocation[i]);
		proof->proofsOfNonRevocation[i] = NULL;
	}
	free(proof);
	proof = NULL;
}

void freeRegistry(struct registry *reg)
{
	if (reg != NULL)
		printf("Implement freeRegistry!!!\n");
}

void freeSignCredential(struct signingCredential * signCre)
{
	if (signCre != NULL)
		printf("Implement freeSignCredential!!!\n");
}

int main()
{
	// init pairing, declare error variables
	pairing_init_set_str(pairing, bncurve);
	int err = 0;
	TPM_RC rc = 0;
	
	// allocate storage for issuer secret key (gamma / isk in document)
	element_t issuerSecret;
	element_init_Zr(issuerSecret, pairing);

	// allocate storage for group public key 
	// 'gpk' = (g1, h1, h2, chi, g2, omega)
	struct groupPublicKey *gpk = (struct groupPublicKey *) malloc(sizeof(struct 
				groupPublicKey));

	// initialize contents of gpk, issuerSecret
	err = setupLaser(issuerSecret, gpk);
	if (err != 0) {
		exit(1);
	}

	// open urandom for generating random bytes
	fp = fopen("/dev/urandom", "r");

	// ISSUER sends nonce (nm)
	uint32_t nm;
	err = fread(&nm, 4, 1, fp);
	if (err != 1) {
		perror("read urandom failed");
		exit(1);
	}	

	uint32_t *ntm = malloc(sizeof(uint32_t));
	if (ntm == NULL) {
		perror("malloc failed");
		exit(1);
	}

	element_t pubTPM;
	element_t ctm;
	element_t sfm;
	element_init_G1(pubTPM, pairing);
	element_init_Zr(ctm, pairing);
	element_init_Zr(sfm, pairing);

	// HOST generates sign 'sigma-m' = (I, nt, ct, sf)
	rc = joinHost(gpk, nm, pubTPM, ntm, ctm, sfm);
	if (rc != 0) {
		perror("problem in createMemKeyHost");
		exit(1);
	}

	// and sends (nm, sigma-m) to Issuer. Issuer returns memCre
	struct membershipCredential * memCre = malloc(
				sizeof(struct membershipCredential));
	if (memCre == NULL) {
		perror("malloc failed");
		exit(1);
	}
	err = joinIssuer(gpk, issuerSecret, nm, pubTPM, 
			*ntm, ctm, sfm, memCre);
	if (err != 0) {
		perror("createMemKeyIssuer failed");
		exit(1);
	}

	// clean up after the initial material
	element_clear(ctm);
	element_clear(sfm);
	free(ntm);

	/* Join done. Membership credential obtained, next getSignCre */
	
	uint32_t ng; 
	err = fread(&ng, 4, 1, fp);
	if (err != 1) {
		perror("read urandom failed");
		exit(1);
	}	

	struct sigmaG *proofForIssuer = malloc(sizeof(struct sigmaG));
	if (proofForIssuer == NULL) {
		perror("malloc failed");
		exit(1);
	}
	proofForIssuer->sigma0 = malloc(sizeof(struct membershipProof));
	if (proofForIssuer->sigma0 == NULL) {
		perror("malloc failed");
		exit(1);
	}
	
	element_t yj; 
	err = proveMembership(pubTPM, gpk, memCre, ng, yj, proofForIssuer->sigma0);
	if (err != 0) {
		perror("proveMembership failed");
		exit(1);
	}
	printf("Membership proof made\n");

	struct basenameRevocationList * baseRL = 
		malloc(sizeof(struct basenameRevocationList));
	generateBaseRL(baseRL_entries, baseRL);
	printf("BaseRL generated \n");

	proofForIssuer->entries = baseRL_entries;
	printf("Proof for issuer made\n");

	err = proveUnrevokedBasename(baseRL, ng, proofForIssuer);
	if (err != 0) {
		perror("proveUnrevokedBasename failed");
		exit(1);
	}
	printf("Unrevoked basename returns\n");

	issuerValidationGetSignCre(baseRL, proofForIssuer, gpk, ng);
	printf("Validation complete\n");

	struct registry *reg = malloc(sizeof(struct registry));
	reg->entries = 0;
	struct signingCredential *signCre = malloc(sizeof(struct signingCredential));

	issuerAliasTokenGeneration(gpk, issuerSecret, proofForIssuer, reg, signCre);
	printf("Alias Tokens generated\n");

	platformFinishTokens(signCre, yj);

	/* End of getSignCre. Can free yj since its now copied into all the alias credentials */
	element_clear(yj);
	freeProofForIssuer(proofForIssuer);

	// clear all the structures and key material, flush handles in TPM
	clearKeyMaterial(pubTPM, issuerSecret, gpk, memCre);
	freeBaseRL(baseRL);
	freeSignCredential(signCre);
	freeRegistry(reg);
	pairing_clear(pairing);
	fclose(fp);
	return 0;
		
	/*

	for (i = 0; i < nr; i++) // nr = baseRL
	{
		// HOST
		t0 = pbc_get_time();
		element_init_G1(Bi[i], pairing);

		curve_data_ptr cdpp = Bi[i]->field->data;
		point_ptr ppt = Bi[i]->data;
		element_t t;

		element_init(t, cdpp->field);
		ppt->inf_flag = 0;

		do {
			element_random(a2i);
			memset(jbuf, 0, sizeof jbuf);
			j = element_to_bytes(jbuf, a2i);
			SHA256(jbuf, strlen((char *)jbuf), obuf);
			element_from_hash(c, obuf, 32);
			element_set(ppt->x, c);

			element_square(t, ppt->x);
			element_add(t, t, cdpp->a);
			element_mul(t, t, ppt->x);
			element_add(t, t, cdpp->b);
		} while (!element_is_sqr(t));
		element_sqrt(ppt->y, t);
		element_clear(t);

		t1 = pbc_get_time();
		host = host + (t1 - t0);
		// send (a2i, Bi[i]->y, B0) to the TPM

		// TPM performs
		// NOAH************************************
		t0 = pbc_get_time();

		element_init_G1(O[i], pairing);
		element_pow_zn(O[i], Bi[i], f);

		element_init_G1(S1[i], pairing);
		element_init_G1(S2[i], pairing);
		element_init_Zr(rp[i], pairing);
		element_random(rp[i]);
		element_pow_zn(S1[i], Bi[i], rp[i]);
		element_pow_zn(S2[i], B0, rp[i]);
		// forward (O[i], S1[i], S2[i]) to Host

		t1 = pbc_get_time();
		tpm = tpm + (t1 - t0);

		// HOST now
		t0 = pbc_get_time();

		element_init_G1(Ki[i], pairing);
		element_random(Ki[i]);
		if (!element_cmp(Ki[i], O[i]))
			printf("GetSignKey C.1.1 3(a) verification not passed! "
			       ":/ \n");

		element_init_Zr(tow[i], pairing);
		element_random(tow[i]);
		element_invert(Ki[i], Ki[i]);
		element_init_G1(P[i], pairing);
		element_mul(P[i], O[i], Ki[i]);
		element_pow_zn(P[i], P[i], tow[i]);

		element_invert(Ki[i], Ki[i]);
		element_init_Zr(rt[i], pairing);
		element_random(rt[i]);
		element_init_G1(RI[i], pairing);
		element_init_G1(RII[i], pairing);
		element_neg(tmpr, rt[i]);

		element_pow2_zn(RI[i], S1[i], tow[i], Ki[i], tmpr);
		element_pow2_zn(RII[i], S2[i], tow[i], K0, tmpr);

		element_init_Zr(cp[i], pairing);
		Hash2(cp[i], B0, K0, Bi[i], Ki[i], P[i], RI[i], RII[i], 0, 0, 0,
		      6);

		// send 'cp[i]' to TPM
		t1 = pbc_get_time();
		host = host + (t1 - t0);

		// TPM: "I'm back"
		// NOAH***************************************
		t0 = pbc_get_time();

		element_init_Zr(nn[i], pairing);
		element_random(nn[i]);

		memset(ibuf, 0, sizeof ibuf);
		memset(jbuf, 0, sizeof jbuf);
		j = element_to_bytes(ibuf, cp[i]);
		j = element_to_bytes(jbuf, nn[i]);
		memcpy(ibuf + lz, jbuf, lz);
		SHA256(ibuf, strlen((char *)ibuf), obuf);
		element_init_Zr(cpt[i], pairing);
		element_from_hash(cpt[i], obuf, 32);

		element_init_Zr(sp[i], pairing);
		element_mul(sp[i], cpt[i], f);
		element_add(sp[i], rp[i], sp[i]);
		// forward (cpt[i], nn[i], sp[i]) to Host

		t1 = pbc_get_time();
		tpm = tpm + (t1 - t0);

		// HOSTtttttt
		t0 = pbc_get_time();
		element_init_Zr(st[i], pairing);
		element_mul(st[i], cpt[i], tow[i]);
		element_add(st[i], rt[i], st[i]);
		element_init_Zr(sv[i], pairing);
		element_mul(sv[i], sp[i], tow[i]);
		// output the signature 'sigma-i = (P[i], nn[i], cpt[i], st[i],
		// sv[i])'

		// Host sends (sig[0],..., sig[nr]) to Issuer
		t1 = pbc_get_time();
		host = host + (t1 - t0);
	}

	// ISSUER to the fore
	t0 = pbc_get_time();

	element_pairing(tmpt, U1, omega);
	element_pairing(tmpt2, U2, g2);

	// compute (B0->y) and set 'B0'

	element_neg(tmpc, ct);
	element_pow2_zn(R1t, B0, sf, K0, tmpc);
	element_pow3_zn(R2t, h1, sf, h2, sal, L, tmpc);

	element_neg(tmpr, ct);
	element_pow2_zn(tmp1, U2, ct, U3, tmpr);
	element_pow3_zn(R3t, U1, sz, h2, sxi, tmp1, one);

	element_neg(tmpc, seta);
	element_pow2_zn(tmp1, h2, tmpc, g1, tmpr);
	element_neg(tmpc, sf);
	element_pow3_zn(R4t, U3, sta, h1, tmpc, tmp1, one);

	Hash2(cj, B0, K0, L, U1, U2, U3, R1t, R2t, R3t, R4t, 9);

	memset(ibuf, 0, sizeof ibuf);
	memset(jbuf, 0, sizeof jbuf);
	j = element_to_bytes(ibuf, cj);
	j = element_to_bytes(jbuf, nt);
	memcpy(ibuf + lz, jbuf, lz);
	SHA256(ibuf, strlen((char *)ibuf), obuf);
	element_from_hash(cq, obuf, 32);

	if (element_cmp(cq, ct))
		printf(
		    "\n GetSignKey Issuer 4(c) verification not passed! :O \n");

	for (i = 0; i < nr; i++) {
		element_neg(tmpr, st[i]);
		element_neg(tmpc, cpt[i]);
		element_pow3_zn(RI[i], Bi[i], sv[i], Ki[i], tmpr, P[i], tmpc);
		element_pow2_zn(RII[i], B0, sv[i], K0, tmpr);

		Hash2(cp[i], B0, K0, Bi[i], Ki[i], P[i], RI[i], RII[i], 0, 0, 0,
		      6);

		memset(ibuf, 0, sizeof ibuf);
		memset(jbuf, 0, sizeof jbuf);
		j = element_to_bytes(ibuf, cp[i]);
		j = element_to_bytes(jbuf, nn[i]);
		memcpy(ibuf + lz, jbuf, lz);
		SHA256(ibuf, strlen((char *)ibuf), obuf);
		element_init_Zr(cqt[i], pairing);
		element_from_hash(cqt[i], obuf, 32);

		if (element_cmp(cqt[i], cpt[i]))
			printf("GetSignKey Issuer 5(Appx.C.1.2) verification "
			       "not passed! >.< \n");

		if (!element_cmp(P[i], one))
			printf("GetSignKey Issuer 5(Appx.C.1.2) P[i] equals "
			       "one! :/ \n");
	}

	element_mul(tmp1, g1, L);

	for (j = 0; j < k; j++) {
		element_init_Zr(x[j], pairing);
		element_init_Zr(beta[j], pairing);
		element_random(x[j]); // Alias Tokens!
		element_random(beta[j]);

		element_add(tmpr, gamma, x[j]);
		element_div(p, one, tmpr);

		element_init_G1(A[j], pairing);
		element_pow2_zn(A[j], tmp1, one, h2, beta[j]);
		element_pow_zn(A[j], A[j], p);
	}

	// append tuple (a10, B0->y, K0, x[0], ..., x[k-1], beta[0], ...,
	// beta[k-1]) to database reg
	// send (A[0], ..., A[k-1], x[0], ..., x[k-1], beta[0], ..., beta[k-1])
	// to Host

	t1 = pbc_get_time();
	iss = iss + (t1 - t0);

	// HOST hi
	t0 = pbc_get_time();

	for (i = 0; i < k; i++) {
		element_init_Zr(y[i], pairing);
		element_add(y[i], alpha, beta[i]);

		// output signCre[i] = (A[i], x[i], y[i])
	}

	t1 = pbc_get_time();
	host = host + (t1 - t0);

	printf("\tTPM, time elapsed %.2fms\n", tpm * 1000);
	printf("\tHost, time elapsed %.2fms\n", host * 1000);
	printf("\tIssuer, time elapsed %.2fms\n\n", iss * 1000);

	tpm = 0;
	host = 0;
	iss = 0;

	// SelectAliasCre --------------------------------------
	// select 'aliasCre[jk]' = (A[jk], x[jk], y[jk])

	// Sign --------------------------------------
	printf("Sign : \n");

	t0 = pbc_get_time();

	// HOST
	// select tuple choosing k
	r = rand();
	r %= k;

	setPoint(D, tw1);

	// send (t2, D->y, h1) to TPM
	t1 = pbc_get_time();
	host = host + (t1 - t0);

	// TPM
	// NOAH**********************************************
	t0 = pbc_get_time();

	element_pow_zn(E, D, f);
	element_random(rf);
	element_pow_zn(S10, D, rf);
	element_pow_zn(S20, h1, rf);
	// forward (E, S10, S20) to Host

	t1 = pbc_get_time();
	tpm = tpm + (t1 - t0) + host;

	// HOST here
	t0 = pbc_get_time();

	element_random(mu);
	element_random(delta);
	element_random(psi);
	element_mul(v, mu, delta);
	element_add(v, v, y[r]);
	element_pow3_zn(hs, g1, one, I, one, h2, y[r]);
	element_invert(tmpr, delta);
	element_pow2_zn(T1, A[r], tmpr, g1, psi);
	element_neg(tmpc, x[r]);
	element_pow2_zn(T2, A[r], tmpc, hs, one);
	element_pow2_zn(T2, T2, tmpr, chi, psi);
	element_pow2_zn(T3, hs, tmpr, h2, mu);

	element_random(rd);
	element_random(rmu);
	element_random(rvi);
	element_random(rpsi);

	element_mul(R1, S10, one);
	element_neg(tmpr, rpsi);
	element_pow2_zn(R2, g1, x[r], chi, one);
	element_pow2_zn(R2, R2, tmpr, h2, rmu);

	element_invert(tmp1, S20);
	element_neg(tmpc, rvi);
	element_pow3_zn(R3, T3, rd, tmp1, one, h2, tmpc);

	Hash2(ch, D, E, T1, T2, T3, R1, R2, R3, x[r], 0, 8);
	// send (ch, M) to TPM

	t1 = pbc_get_time();
--
	element_clear(R4t);
	element_clear(tmp1);
	element_clear(tmp11);
	element_clear(tmp2);
	element_clear(tmp22);
	element_clear(tmpt);
	element_clear(tmpt2);
	element_clear(tmpr);
	element_clear(tmpc);
	element_clear(f);
	element_clear(p);
	element_clear(z);
	element_clear(delta);
	element_clear(alpha);
	element_clear(theta);
	element_clear(eeta);
	element_clear(mu);
	element_clear(v);
	element_clear(a1j);
	element_clear(a2i);
	element_clear(psi);
	element_clear(rho);
	element_clear(xi);
	element_clear(rd);
	element_clear(rf);
	element_clear(rz);
	element_clear(rxi);
	element_clear(reta);
	element_clear(ral);
	element_clear(rta);
	element_clear(rvi);
	element_clear(rmu);
	element_clear(rpsi);
	element_clear(sd);
	element_clear(sf);
	element_clear(sz);
	element_clear(sxi);
	element_clear(seta);
	element_clear(sal);
	element_clear(sta);
	element_clear(svi);
	element_clear(spsi);
	element_clear(smu);
	element_clear(ch);
	element_clear(ct);
	element_clear(cq);
	element_clear(cj);
	element_clear(c);
	element_clear(one);
	element_clear(tw1);
	pairing_clear(pairing);
	*/
}
