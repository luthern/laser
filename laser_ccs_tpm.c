#include "laser.h"
#include "laser_tpm.h"

uint64_t aliasTokensPerSignCre = 100, baseRL_entries = 1,
	 signCredentialsToGen = 2, numSignatures = 1;
double t0 = 0, t1 = 0, 
       tpm_online = 0, host_online = 0, issuer_online = 0,
       tpm_offline = 0, host_offline = 0, issuer_offline = 0;
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
	uint64_t length;
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
	length = 6 * l1;

	if (q > 7) {
		element_to_bytes(jbuf, Rt);
		memcpy(ibuf + 7 * l1, jbuf, l1);
		element_to_bytes(jbuf, Re);
		memcpy(ibuf + 8 * l1, jbuf, l1);
		length += 2 * l1;
	}
	if (q > 9) {
		element_to_bytes(jbuf, Rf);
		memcpy(ibuf + 9 * l1, jbuf, l1);
		length += l1;
	}

	SHA256(ibuf, length, obuf);
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
	double host_offset = 0;
	t0 = pbc_get_time();
	TPM_RC rc = 0;
	element_t Rm;
	element_t chm;
	element_init_G1(Rm, pairing);
	element_init_Zr(chm, pairing);
	
	/* joinP1 */
	double *time_taken = malloc(sizeof(double));
	unsigned char I_x[32];
	unsigned char I_y[32];
	rc = joinP1(I_x, I_y, time_taken);
	if (rc != 0)
	{
		perror("joinP1 failed");
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
	tpm_offline += *time_taken;
	host_offset += *time_taken;

	/* joinP2 */
	uint16_t *commit_cntr = malloc(sizeof(uint16_t));

	unsigned char pt_buf[64];
	element_to_bytes(pt_buf, gpk->h1);
	unsigned char Rm_buf[64];

	rc = joinP2(pt_buf, pt_buf + 32, Rm_buf, Rm_buf + 32, commit_cntr, time_taken);
	if (rc != 0)
	{
		perror("joinP2 failed");
		element_clear(Rm);
		element_clear(chm);
		free(time_taken);
		free(commit_cntr);
		return rc;
	}
	element_from_bytes(Rm, Rm_buf);
	tpm_offline += *time_taken;
	host_offset += *time_taken;

	/* joinP3 4(b) */
	Hash1(pubTPM, Rm, chm);
	/* joinP3 */

	unsigned char ctm_buf[32];
	unsigned char chm_buf[32];
	unsigned char sfm_buf[32];

	element_to_bytes(chm_buf, chm);
	rc = joinP3(*commit_cntr, nm, chm_buf, ntm, ctm_buf, sfm_buf, time_taken);
	if (rc != 0) 
	{
		perror("joinP3 failed");
		element_clear(Rm);
		element_clear(chm);
		free(time_taken);
		free(commit_cntr);
		return rc;
	}		
	// output ctm, sfm
	element_from_bytes(ctm, ctm_buf);
	element_from_bytes(sfm, sfm_buf);
	tpm_offline += *time_taken;
	host_offset += *time_taken;

	free(time_taken);
	free(commit_cntr);
	element_clear(Rm);
	element_clear(chm);

	t1 = pbc_get_time();
	host_offline += t1 - t0 - host_offset;
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

	unsigned char buffer[32 + 2 * sizeof(uint32_t)];
	unsigned char hashout[32];

	element_neg(temp, ctm);
	element_pow2_zn(Rm_hat, gpk->h1, sfm, pubTPM, temp);
	Hash1(pubTPM, Rm_hat, chm_hat);	
	element_clear(temp);
	
	element_to_bytes(buffer, chm_hat);
	memcpy(buffer + 32, &ntm, sizeof(uint32_t));
	memcpy(buffer + 32 + sizeof(uint32_t), &nm, sizeof(uint32_t));
	SHA256(buffer, 32 + 2 * sizeof(uint32_t), hashout);
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
	t0 = pbc_get_time();
	double host_offset = 0;
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

	rc = getSignCreP1(pt_buf, pt_buf + 32, a10_buf, b20_buf,
			K0_buf, K0_buf + 32, S10_buf, S10_buf + 32, 
			S20_buf, S20_buf + 32, commit_cntr, time_taken);
	if (rc != 0)
	{
		perror("getSignCreP1 failed");
		free(time_taken);
		free(commit_cntr);
		// TODO: What else needs freed here??
		exit(1);
	} else
		printf("getSignCreP1 complete\n");
	
	tpm_offline += *time_taken;
	host_offset += *time_taken;

	element_from_bytes(sigma0->K0, K0_buf);
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

	/* TPM getSignCreP2 */
	unsigned char ct0_buf[32];
	unsigned char sf0_buf[32];
	unsigned char ch0_buf[32];
	element_to_bytes(ch0_buf, ch0);

	rc = getSignCreP2(*commit_cntr, ng, ch0_buf, &sigma0->nt0, 
			ct0_buf, sf0_buf, time_taken);
	if (rc != 0) {
		perror("getSignCreP2 failed");
		free(commit_cntr);
		free(time_taken);
		element_clear(ch0);
		// TODO: What else needs freed here??
		exit(1);
	}
	else
		printf("getSignCreP2 complete\n");
	tpm_offline += *time_taken;
	host_offset += *time_taken;
	free(commit_cntr);
	free(time_taken);

	element_from_bytes(sigma0->ct0, ct0_buf);
	element_from_bytes(sigma0->sf0, sf0_buf);
	
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
	t1 = pbc_get_time();
	host_offline += t1 - t0 - host_offset;
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
}

int singleBasenameProof(int index, uint32_t ng,
	       	struct revocationListEntry *revEntry, struct sigmaG *sigmaG)
{
	TPM_RC rc = 0;
	double host_offset = 0;
	t0 = pbc_get_time();

	sigmaG->proofsOfNonRevocation[index] = malloc(sizeof(struct basenameProof));
	struct basenameProof *proof = sigmaG->proofsOfNonRevocation[index];
	element_init_G1(proof->Pi, pairing);
	element_init_Zr(proof->cti, pairing);
	element_init_Zr(proof->staui, pairing);
	element_init_Zr(proof->svi, pairing);
	
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
	rc = getSignCreP3(B0_buf, B0_buf + 32, a1i_buf, Bi_buf + 32,
			Oi_buf, Oi_buf + 32, S1i_buf, S1i_buf + 32, S2i_buf, S2i_buf + 32,
			commit_cntr, time_taken);
	if (rc != 0) {
		perror("getSignCreP3 failed");
		free(commit_cntr);
		free(time_taken);
		// TODO: What else needs freed here??
		return rc;
	} 
	//else
	//	printf("getSignCreP3 complete\n");
	tpm_offline += *time_taken;
	host_offset += *time_taken;
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
	} 
	//else {
	//	printf("GetSignCre (4)(c) passed\n");
	//}

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

	rc = getSignCreP4(*commit_cntr, ng, chi_buf, &proof->nti, 
			cti_buf, sfi_buf, time_taken);
	if (rc != 0) {
		perror("getSignCreP4 failed");
		element_clear(taui);
		element_clear(rtaui);
		free(commit_cntr);
		free(time_taken);
		// TODO: What else needs freed here??
		return rc;
	} 
	//else
	//	printf("getSignCreP4 complete\n");

	tpm_offline += *time_taken;
	host_offset += *time_taken;
	free(commit_cntr);
	free(time_taken);
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
	t1 = pbc_get_time();
	host_offline += t1 - t0 - host_offset;
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
	} 
	//else {
	//	printf("Issuer verification of membership (6)(a) passed\n");
	//}
	
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
	memcpy(hash_buf + 32, &sigma0->nt0, sizeof(uint32_t));
	memcpy(hash_buf + 32 + sizeof(uint32_t), &ng, sizeof(uint32_t));
	SHA256(hash_buf, 32 + (2 * sizeof(uint32_t)), ct0_hat_buf);
	element_t ct0_hat;
	element_init_Zr(ct0_hat, pairing);
	element_from_hash(ct0_hat, ct0_hat_buf, 32);

	if (element_cmp(ct0_hat, sigma0->ct0)) {
		printf("GetSignKey Issuer Membership Verification (6)(d) not passed!\n");
		element_clear(ct0_hat);
		element_clear(ch0_hat);
		return 1;
	} 
	//else {
	//	printf("GetSignKey Issuer Membership Verification (6)(d) passed!\n");
	//}
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
	
	unsigned char buffer[32 + 2 * sizeof(uint32_t)];
	unsigned char cti_hat_buf[32];
	element_to_bytes(buffer, chi_hat);
	memcpy(buffer + 32, &baseProof->nti, sizeof(uint32_t));
	memcpy(buffer + 32 + sizeof(uint32_t), &ng, sizeof(uint32_t));
	SHA256(buffer, 32 + 2* sizeof(uint32_t), cti_hat_buf);
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
	signCre->aliasTokenList = malloc(aliasTokensPerSignCre * 
			sizeof(struct aliasCredential *));
	reg->registryEntries = malloc(aliasTokensPerSignCre * 
			sizeof(struct registryEntry *));
	
	int i;
	// TODO: More flexible registry allocation of memory so we can add more tokens
	// and have more than one signCredential. This is not possible with current code.
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

		// TODO: Make the registry hold a single record per a10, b20, K0 set
		// instead of one per xjk...?
		reg->registryEntries[reg->entries] = malloc(sizeof(struct registryEntry));
		element_init_Zr(reg->registryEntries[reg->entries]->a10, pairing);
		element_init_Zr(reg->registryEntries[reg->entries]->b20, pairing);
		element_init_G1(reg->registryEntries[reg->entries]->K0, pairing);
		element_init_Zr(reg->registryEntries[reg->entries]->xjk, pairing);
		element_set(reg->registryEntries[reg->entries]->a10, proof->sigma0->a10);
		element_set(reg->registryEntries[reg->entries]->b20, proof->sigma0->b20);
		element_set(reg->registryEntries[reg->entries]->K0, proof->sigma0->K0);
		element_set(reg->registryEntries[reg->entries]->xjk, xjk);

		element_clear(xjk);
		element_clear(zjk);
		element_clear(Ajk);
		element_clear(one);
		element_clear(exponent);
		signCre->aliasTokenList[i]->used = 0;
		reg->entries++;
	}	
}
void platformFinishTokens(struct signingCredential *signCre, element_t yj)
{
	int i;
	for (i = 0; i < aliasTokensPerSignCre; i++) {
		element_init_Zr(signCre->aliasTokenList[i]->yj, pairing);
		element_set(signCre->aliasTokenList[i]->yj, yj);
	}
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
	if (reg == NULL)
		return;
	int i;
	for (i = 0; i < reg->entries; i++) {
		element_clear(reg->registryEntries[i]->a10);
		element_clear(reg->registryEntries[i]->b20);
		element_clear(reg->registryEntries[i]->xjk);
		element_clear(reg->registryEntries[i]->K0);
		free(reg->registryEntries[i]);
		reg->registryEntries[i] = NULL;
	}
	free(reg);
	reg = NULL;
}

int generateSignCredentials(element_t pubTPM, struct membershipCredential *memCre, 
		element_t issuerSecret, struct sigmaG *proofForIssuer, 
		struct groupPublicKey *gpk, struct basenameRevocationList *baseRL,
		struct registry *reg, struct identitiesList *identitiesList
	      )
{
	      // TODO: Generate variable signing credentials instead of 1. 100 alias tokens each
	int i;
	int err = 0;
	for (i = 0; i < signCredentialsToGen; i++) {
		t0 = pbc_get_time();
		uint32_t ng; 
		err = fread(&ng, 4, 1, fp);
		if (err != 1) {
			perror("read urandom failed");
			exit(1);
		}	

		proofForIssuer = malloc(sizeof(struct sigmaG));
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
		t1 = pbc_get_time();
		host_offline += t1 - t0;
		err = proveMembership(pubTPM, gpk, memCre, ng, yj, proofForIssuer->sigma0);
		if (err != 0) {
			perror("proveMembership failed");
			exit(1);
		}
		printf("Membership proof made\n");
	
		proofForIssuer->entries = baseRL_entries;
		err = proveUnrevokedBasename(baseRL, ng, proofForIssuer);
		if (err != 0) {
			perror("proveUnrevokedBasename failed");
			exit(1);
		}
		t0 = pbc_get_time();
		printf("Unrevoked basename returns\n");

		issuerValidationGetSignCre(baseRL, proofForIssuer, gpk, ng);
		printf("Validation of SignCre complete\n");

		reg = malloc(sizeof(struct registry));
		reg->entries = 0;
		identitiesList->credentials[i] = malloc(sizeof(struct signingCredential));

		issuerAliasTokenGeneration(gpk, issuerSecret, proofForIssuer, reg,
				identitiesList->credentials[i]);
		printf("Alias Tokens generated\n");
		t1 = pbc_get_time();
		issuer_offline += t1 - t0;

		platformFinishTokens(identitiesList->credentials[i], yj);

		t0 = pbc_get_time();
		element_clear(yj);
		freeProofForIssuer(proofForIssuer);
		freeRegistry(reg);
		// Clear sign credential unless it's the last one
		// We use the last one for a signature
		printf("SignCre %d generated\n", i);
	}
	return 0;
}

void initSignatureStructure(struct laserSignature *sig)
{
	int err = fread(&sig->nts, 4, 1, fp);
	if (err != 1) {
		perror("read urandom failed");
		exit(1);
	}	
	element_init_Zr(sig->xjk, pairing);
	element_init_Zr(sig->a1s, pairing);
	element_init_Zr(sig->b2s, pairing);
	element_init_G1(sig->Ks, pairing);
	element_init_G1(sig->T1, pairing);
	element_init_G1(sig->T2, pairing);
	element_init_G1(sig->T3, pairing);
	element_init_Zr(sig->cts, pairing);
	element_init_Zr(sig->sfs, pairing);
	element_init_Zr(sig->sz, pairing);
	element_init_Zr(sig->sdelta, pairing);
	element_init_Zr(sig->smu, pairing);
	element_init_Zr(sig->sv, pairing);
}

int signMessage(struct groupPublicKey *gpk, element_t pubTPM, 
		struct aliasCredential *alias, char *message,
		struct laserSignature *sig)
{
	double host_offset = 0;
	t0 = pbc_get_time();
	TPM_RC rc = 0;

	initSignatureStructure(sig);
	element_set(sig->xjk, alias->xjk);
	element_t Bs;
	element_init_G1(Bs, pairing);

	//SetPoint 'Bs', a1s is the preimage of Bs->x
	setPoint(Bs, sig->a1s);
	
	/* Copy Bs->y into sig->b2s */
	unsigned char b2s_buf[32];
	element_to_bytes(b2s_buf, element_y(Bs));
	element_from_bytes(sig->b2s, b2s_buf);
	
	/* TPM Signature Part 1 */
	uint16_t *commit_cntr = malloc(sizeof(uint16_t));
	double *time_taken = malloc(sizeof(double));

	unsigned char h1_buf[64];
	element_to_bytes(h1_buf, gpk->h1);

	unsigned char a1s_buf[32];
	element_to_bytes(a1s_buf, sig->a1s);
	unsigned char Ks_buf[64];
	unsigned char S1s_buf[64];
	unsigned char S2s_buf[64];	
	rc = signP1(h1_buf, h1_buf + 32, a1s_buf, b2s_buf,
		Ks_buf, Ks_buf + 32, S1s_buf, S1s_buf + 32, 
		S2s_buf, S2s_buf + 32, commit_cntr, time_taken);
	if (rc != 0) {
		perror("signP1 failed");
		free(time_taken);
		free(commit_cntr);
		// TODO: What else needs freed here??	
		return rc;
	} else
		printf("signP1 complete\n");
	host_offset += *time_taken;
	tpm_online += *time_taken;
	element_t S1s, S2s;
	element_init_G1(S1s, pairing);
	element_init_G1(S2s, pairing);
	element_from_bytes(sig->Ks, Ks_buf);
	element_from_bytes(S1s, S1s_buf);
	element_from_bytes(S2s, S2s_buf);

	element_t mu, delta, v, hs;
	element_init_Zr(mu, pairing);
	element_init_Zr(delta, pairing);
	element_init_Zr(v, pairing);
	element_init_G1(hs, pairing);

	element_t one;
	element_init_Zr(one, pairing);
	element_set1(one);
	
	/* Compute mu, delta, v, hs */
	element_random(mu);
	element_random(delta);
	element_mul(v, mu, delta);
	element_add(v, v, alias->yj);
	element_mul(hs, pubTPM, gpk->g1);
	element_pow3_zn(hs, hs, one, gpk->h2, alias->yj, gpk->h3, alias->xjk); 
	
	/* Compute T1, T2, T3 */
	element_t inv_delta;
	element_init_Zr(inv_delta, pairing);
	element_invert(inv_delta, delta);

	element_t neg_zjk;
	element_init_Zr(neg_zjk, pairing);
	element_neg(neg_zjk, alias->zjk);

	element_pow_zn(sig->T1, alias->Ajk, inv_delta);
	element_pow2_zn(sig->T2, alias->Ajk, neg_zjk, hs, one);
	element_pow_zn(sig->T2, sig->T2, inv_delta);
	element_pow2_zn(sig->T3, hs, inv_delta, gpk->h2, mu);

	/* Compute R1s, R2s, R3s */
	element_t rz, rdelta, rmu, rv;
	element_init_Zr(rz, pairing);
	element_init_Zr(rdelta, pairing);
	element_init_Zr(rmu, pairing);
	element_init_Zr(rv, pairing);
	element_random(rz);
	element_random(rdelta);
	element_random(rmu);
	element_random(rv);

	element_t neg_one;
	element_init_Zr(neg_one, pairing);
	element_neg(neg_one, one);

	element_t neg_rv;
	element_init_Zr(neg_rv, pairing);
	element_neg(neg_rv, rv);

	element_t R1s, R2s, R3s;
	element_init_G1(R1s, pairing);
	element_init_G1(R2s, pairing);
	element_init_G1(R3s, pairing);

	element_set(R1s, S1s);
	element_pow2_zn(R2s, sig->T1, rz, gpk->h2, rmu);
	element_pow3_zn(R3s, sig->T3, rdelta, S2s, neg_one, gpk->h2, neg_rv);
	
	element_t chs;
	element_init_Zr(chs, pairing);
	Hash2(chs, sig->xjk, Bs, sig->Ks, sig->T1, sig->T2, 
			sig->T3, R1s, R2s, R3s, NULL, 9); 
	
	unsigned char chs_buf[32];
	element_to_bytes(chs_buf, chs);
	unsigned char sfs_buf[64];
	unsigned char cts_buf[64];

	rc = signP2(*commit_cntr, chs_buf, message, strlen(message), 
			&sig->nts, cts_buf, sfs_buf, time_taken);
	if (rc != 0) {
		perror("signP2 failed");
		free(time_taken);
		free(commit_cntr);
		// TODO: What else needs freed here??
		return rc;
	}
	host_offset += *time_taken;
	tpm_online += *time_taken;
	element_from_bytes(sig->sfs, sfs_buf);
	element_from_bytes(sig->cts, cts_buf);

	/* Compute sz, sdelta, smu, sv */
	element_mul(sig->sz, sig->cts, alias->zjk);
	element_add(sig->sz, sig->sz, rz);
	element_mul(sig->sdelta, sig->cts, delta);
	element_add(sig->sdelta, sig->sdelta, rdelta);
	element_mul(sig->smu, sig->cts, mu);
	element_add(sig->smu, sig->smu, rmu);
	element_mul(sig->sv, sig->cts, v);
	element_add(sig->sv, sig->sv, rv);

	element_clear(chs);
	element_clear(rz);
	element_clear(rdelta);
	element_clear(rmu);
	element_clear(rv);
	element_clear(inv_delta);
	element_clear(neg_zjk);
	element_clear(neg_rv);
	element_clear(neg_one);
	element_clear(R1s);
	element_clear(R2s);
	element_clear(R3s);
	element_clear(mu);
	element_clear(delta);
	element_clear(v);
	element_clear(hs);
	element_clear(one);
	element_clear(S1s);
	element_clear(S2s);
	free(commit_cntr);
	free(time_taken);
	t1 = pbc_get_time();
	host_online += t1 - t0 - host_offset;
	alias->used = 1;
	return 0;
}

int verifySignature(struct groupPublicKey *gpk, struct laserSignature *sig,
		char *message, struct aliasTokenRevocationList *atRL)
{
	/* Verify validity */
	unsigned char Bs_buf[64];
	unsigned char a1s_buf[32];
	element_to_bytes(a1s_buf, sig->a1s);
	SHA256(a1s_buf, 32, Bs_buf);
	element_to_bytes(Bs_buf + 32, sig->b2s);
	element_t Bs;
	element_init_G1(Bs, pairing);
	element_from_bytes(Bs, Bs_buf);

	element_t pairing_T1_omega, pairing_T2_g2;
	element_init_GT(pairing_T1_omega, pairing);
	element_init_GT(pairing_T2_g2, pairing);

	element_pairing(pairing_T1_omega, sig->T1, gpk->omega);	
	element_pairing(pairing_T2_g2, sig->T2, gpk->g2);

	if (element_cmp(pairing_T1_omega, pairing_T2_g2)) {
		printf("Verification of validity (1)(b) failed\n");
		element_clear(pairing_T1_omega);
		element_clear(pairing_T2_g2);
		element_clear(Bs);
		return 1;
	} else {
		printf("Verification of validity (1)(b) succeeded\n");
	}
	element_clear(pairing_T1_omega);
	element_clear(pairing_T2_g2);

	element_t R1s_hat, R2s_hat, R3s_hat;
	element_init_G1(R1s_hat, pairing);
	element_init_G1(R2s_hat, pairing);
	element_init_G1(R3s_hat, pairing);
	
	element_t neg_cts, neg_sfs, neg_sv, neg_xjk, one, exponent;
	element_init_Zr(neg_cts, pairing);
	element_neg(neg_cts, sig->cts);
	element_init_Zr(neg_sfs, pairing);
	element_neg(neg_sfs, sig->sfs);
	element_init_Zr(neg_sv, pairing);
	element_neg(neg_sv, sig->sv);
	element_init_Zr(neg_xjk, pairing);
	element_neg(neg_xjk, sig->xjk);
	element_init_Zr(one, pairing);
	element_set1(one);
	element_init_Zr(exponent, pairing);

	element_pow2_zn(R1s_hat, Bs, sig->sfs, sig->Ks, neg_cts);
	element_pow2_zn(R2s_hat, sig->T1, sig->sz, gpk->h2, sig->smu);
	element_pow3_zn(R2s_hat, R2s_hat, one, sig->T2, sig->cts, sig->T3, neg_cts);
	element_pow3_zn(R3s_hat, sig->T3, sig->sdelta, 
			gpk->h1, neg_sfs, gpk->h2, neg_sv);
	element_mul(exponent, neg_xjk, sig->cts);
	element_pow3_zn(R3s_hat, R3s_hat, one, gpk->g1, neg_cts, gpk->h3, exponent); 
	
	element_clear(neg_cts);
	element_clear(neg_sfs);
	element_clear(neg_sv);
	element_clear(neg_xjk); 
	element_clear(one);
	element_clear(exponent);
	
	element_t chs_hat;
	element_init_Zr(chs_hat, pairing);

	Hash2(chs_hat, sig->xjk, Bs, sig->Ks, sig->T1, sig->T2, sig->T3, 
			R1s_hat, R2s_hat, R3s_hat, NULL, 9);
	element_clear(Bs);
	element_clear(R1s_hat);
	element_clear(R2s_hat);
	element_clear(R3s_hat);

	unsigned char buffer[32 + sizeof(uint32_t) + strlen(message)];
	element_to_bytes(buffer, chs_hat);
	memcpy(buffer + 32, &sig->nts, sizeof(uint32_t));
	memcpy(buffer + 32 + sizeof(uint32_t), message, strlen(message));
	
	unsigned char cts_buf[32];
	element_t cts_hat;
	element_init_Zr(cts_hat, pairing);
	SHA256(buffer, 32 + sizeof(uint32_t) + strlen(message), cts_buf);
	element_from_bytes(cts_hat, cts_buf);

	if (element_cmp(cts_hat, sig->cts)) {
		printf("Signature verification failed\n");
		
	} else {
		printf("Verified signature!\n");
	}

	/* Verify unrevoked */
	if (atRL != NULL) {
		// token-based revocation list atRL...
	}

	return 0;
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

void freeSignCredential(struct signingCredential * signCre)
{
	if (signCre != NULL)
		return;
	int i;
	for (i = 0; i < signCre->entries; i++) {
		element_clear(signCre->aliasTokenList[i]->Ajk);
		element_clear(signCre->aliasTokenList[i]->zjk);
		element_clear(signCre->aliasTokenList[i]->yj);
		element_clear(signCre->aliasTokenList[i]->xjk);
		free(signCre->aliasTokenList[i]);
		signCre->aliasTokenList[i] = NULL;
	}
	free(signCre);
	signCre = NULL;
}

void freeIdentitiesList(struct identitiesList *idList)
{
	int i;
	for (i = 0; i < signCredentialsToGen; i++) {
		freeSignCredential(idList->credentials[i]);
	}
	free(idList->credentials);
	free(idList);
}

void freeSignature(struct laserSignature *sig)
{
	element_clear(sig->xjk);
	element_clear(sig->a1s);
	element_clear(sig->b2s);
	element_clear(sig->Ks);
	element_clear(sig->T1);
	element_clear(sig->T2);
	element_clear(sig->T3);
	element_clear(sig->cts);
	element_clear(sig->sfs);
	element_clear(sig->sz);
	element_clear(sig->sdelta);
	element_clear(sig->smu);
	element_clear(sig->sv);
	free(sig);
	sig = NULL;
}

int main(int argc, char *argv[])
{
	uint64_t option;
	if (argc < 6) {
		printf("Usage: ccs_exe NumSignCredentials aliasTokensPerSignCre"
			       "NumSignatures NumRevoked Option\n"
				"Options:\n0 Classical DAA," 
				"one signature per sign credential\n"
				"1 All signatures on first sign credential\n");
		exit(0);
	}

	signCredentialsToGen = (uint64_t) strtol(argv[1], NULL, 10);
	aliasTokensPerSignCre = (uint64_t) strtol(argv[2], NULL, 10);
	baseRL_entries = (uint64_t) strtol(argv[3], NULL, 10);
	numSignatures = (uint64_t) strtol(argv[4], NULL, 10);
	option = (uint64_t) strtol(argv[5], NULL, 10);

	if (option && numSignatures > aliasTokensPerSignCre) {
		printf("For option 1 NumSignatures must be less than"
				"aliasTokensPerSignCre\n");
		exit(1);
	}
	else if (!option && numSignatures > signCredentialsToGen) {
		printf("For option 0 NumSignatures must be less than"
				"NumSignCredentials\n");
		exit(1);
	}

	t0 = pbc_get_time();
	// init pairing, declare error variables
	pairing_init_set_str(pairing, bncurve);
	int err = 0;
	TPM_RC rc = 0;
	
	// allocate storage for issuer secret key (gamma / isk in document)
	element_t issuerSecret;
	element_init_Zr(issuerSecret, pairing);

	// allocate storage for group public key 
	// 'gpk' = (g1, h1, h2, chi, g2, omega)
	struct groupPublicKey *gpk = malloc(sizeof(struct groupPublicKey));

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
	t1 = pbc_get_time();
	issuer_offline += t1 - t0;

	element_t pubTPM;
	element_t ctm;
	element_t sfm;
	element_init_G1(pubTPM, pairing);
	element_init_Zr(ctm, pairing);
	element_init_Zr(sfm, pairing);

	// HOST generates sign 'sigma-m' = (I, nt, ct, sf)
	rc = joinHost(gpk, nm, pubTPM, ntm, ctm, sfm);
	if (rc != 0) {
		perror("problem in joinHost");
		exit(1);
	}
	
	t0 = pbc_get_time();
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
		perror("joinIssuer failed");
		exit(1);
	}

	// clean up after the initial material
	element_clear(ctm);
	element_clear(sfm);
	free(ntm);
	t1 = pbc_get_time();
	issuer_offline += t1 - t0;
	/* Join done. Membership credential obtained, next getSignCre */
	
	// Generate BaseRL once
	struct basenameRevocationList * baseRL = 
			malloc(sizeof(struct basenameRevocationList));
	generateBaseRL(baseRL_entries, baseRL);
	printf("BaseRL generated \n");

	struct sigmaG *proofForIssuer = NULL;
	struct registry *reg = NULL;
	
	struct identitiesList * identitiesList = malloc(sizeof(struct identitiesList));
	identitiesList->credentials = malloc(signCredentialsToGen * 
			sizeof(struct signingCredential *)); 
	
	err = generateSignCredentials(pubTPM, memCre, 
		issuerSecret, proofForIssuer, 
		gpk, baseRL, reg, identitiesList);

	struct laserSignature *sig;
	char * message = "MESSAGE";

	// TODO: Compute multiple signatures either with the same or different signCre	

	if (option) {
		// sign all on signCredential 0
		for (int i = 0; i < numSignatures; i++) {
			sig = malloc(sizeof(struct laserSignature));
			err = signMessage(gpk, pubTPM, 
				identitiesList->credentials[0]->aliasTokenList[i],
				message, sig);
			if (err) {
				printf("Error in signature\n");
			}
			t0 = pbc_get_time();
			err = verifySignature(gpk, sig, message, NULL);
			if (err) {
				printf("Error in verify signature\n");
			}
			t1 = pbc_get_time();
			issuer_online += t1 - t0;
			freeSignature(sig);
		}
	}
	else {
		// sign all on separate signCredentials
		for (int i = 0; i < numSignatures; i++) {
			sig = malloc(sizeof(struct laserSignature));
			err = signMessage(gpk, pubTPM, 
				identitiesList->credentials[i]->aliasTokenList[0],
				message, sig);
			if (err) {
				printf("Error in signature\n");
			}
			t0 = pbc_get_time();
			err = verifySignature(gpk, sig, message, NULL);
			if (err) {
				printf("Error in verify signature\n");
			}
			t1 = pbc_get_time();
			issuer_online += t1 - t0;
			freeSignature(sig);
		}
	}
	
	// clear all the structures and key material, flush handles in TPM
	rc = flush_handles();
	if (rc != 0)
	{
		perror("flush_handles failed");
		exit(1);
	}
	freeIdentitiesList(identitiesList);
	//freeRegistry(reg);
	clearKeyMaterial(pubTPM, issuerSecret, gpk, memCre);
	freeBaseRL(baseRL);
	pairing_clear(pairing);
	fclose(fp);
	printf("TPM Offline: %.2fms\n", tpm_offline * 1000);
	printf("Host Offline: %.2fms\n", host_offline * 1000);
	printf("Issuer Offline: %.2fms\n", issuer_offline * 1000);
	printf("TPM Online: %.2fms\n", tpm_online * 1000);
	printf("Host Online: %.2fms\n", host_online * 1000);
	printf("Issuer Online: %.2fms\n", issuer_online * 1000);
	return 0;
}
