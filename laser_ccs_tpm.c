#include "laser.h"
#include "laser_tpm.h"

int i, j, k = 100, nr = 256;
double t0 = 0, t1 = 0, tpm = 0, host = 0, iss = 0;
static pairing_t pairing;
static FILE *fp;

void Hash1(element_t z1, element_t z2, element_t z)
{
	memset(ibuf, 0, sizeof ibuf);
	memset(jbuf, 0, sizeof jbuf);
	j = element_to_bytes(jbuf, z1);
	j = element_to_bytes(jbuf, z2);
	memcpy(ibuf + l1, jbuf, l1);
	SHA256(ibuf, 2 * l1, obuf);
	element_from_hash(z, obuf, 32);
}

void setPoint(element_t Bj, element_t a1j)
{
	element_t z;
	element_init_Zr(z, pairing);

	curve_data_ptr cdp = Bj->field->data;
	point_ptr pt = Bj->data;
	element_t t;

	element_init(t, cdp->field);
	pt->inf_flag = 0;

	do {
		element_random(a1j);
		memset(jbuf, 0, sizeof jbuf);
		j = element_to_bytes(jbuf, a1j);
		SHA256(jbuf, strlen((char *)ibuf), obuf);
		element_from_hash(z, obuf, 32);
		element_set(pt->x, z);

		element_square(t, pt->x);
		element_add(t, t, cdp->a);
		element_mul(t, t, pt->x);
		element_add(t, t, cdp->b);
	} while (!element_is_sqr(t));
	element_sqrt(pt->y, t);

	element_clear(t);
	element_clear(z);
}

void Hash2(element_t z, element_t B, element_t K, element_t L, element_t Uo,
	   element_t Ut, element_t Ue, element_t Ro, element_t Rt, element_t Re,
	   element_t Rf, int q)
{
	memset(ibuf, 0, sizeof ibuf);
	memset(jbuf, 0, sizeof jbuf);
	j = element_to_bytes(ibuf, B);
	j = element_to_bytes(jbuf, K);
	memcpy(ibuf + l1, jbuf, l1);
	j = element_to_bytes(jbuf, L);
	memcpy(ibuf + 2 * l1, jbuf, l1);
	j = element_to_bytes(jbuf, Uo);
	memcpy(ibuf + 3 * l1, jbuf, l1);
	j = element_to_bytes(jbuf, Ut);
	memcpy(ibuf + 4 * l1, jbuf, l1);
	j = element_to_bytes(jbuf, Ue);
	memcpy(ibuf + 5 * l1, jbuf, l1);
	j = element_to_bytes(jbuf, Ro);
	memcpy(ibuf + 6 * l1, jbuf, l1);

	if (q > 7) {
		j = element_to_bytes(jbuf, Rt);
		memcpy(ibuf + 7 * l1, jbuf, l1);
		j = element_to_bytes(jbuf, Re);
		memcpy(ibuf + 8 * l1, jbuf, l1);
	}
	if (q > 8) {
		j = element_to_bytes(jbuf, Rf);
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
	element_init_G1(gpk->chi, pairing);
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

	element_pow_zn(gpk->chi, gpk->g1, issuerSecret);
	element_pow_zn(gpk->omega, gpk->g2, issuerSecret);

	return 0;
}

TPM_RC createMemKeyHost(struct groupPublicKey * const gpk, uint32_t nim, 
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
	// NEED TO HASH nim into chm <-- Pranav is working on this. 
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

int createMemKeyIssuer(struct groupPublicKey * const gpk, element_t issuerSecret, uint32_t nim,
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
	element_init_Zr(memCre->z, pairing);
	element_init_Zr(memCre->rho, pairing);
	element_random(memCre->z);
	element_random(memCre->rho);

	element_t exponent;
	element_init_Zr(exponent, pairing);
	
	element_add(exponent, issuerSecret, memCre->z);
	element_invert(exponent, exponent);
	element_pow_zn(temp, gpk->h2, memCre->rho);
	element_mul(temp, pubTPM, temp);
	element_mul(temp, gpk->g1, temp);
	element_pow_zn(memCre->J, temp, exponent);

	/* Clean up temporary variables */
	element_clear(temp);
	element_clear(exponent);

	return 0;
}

int provePF_Membership(element_t pubTPM, struct groupPublicKey *gpk, 
		struct membershipCredential *memCre, struct signatureSigma0 *sigma0)
{
	element_t sigma0->a1j;
	element_t Bj;
	element_init_Zr(sigma0->a1j, pairing);
	element_init_G1(Bj, pairing);

	//SetPoint 'Bj'
	setPoint(Bj, sigma0->a1j);

	//TPM action
	//TPM2_commit : createMemKeyP2(sigma0->a1j, sigma0->b2j (Bj->y), gpk->h1)
	//output : (sigma0->Kj, S10, S20)

	element_t alpha, theta, xi, eeta;
	element_init_Zr(alpha, pairing);
	element_init_Zr(theta, pairing);
	element_init_Zr(xi, pairing);
	element_init_Zr(eeta, pairing);

  	element_random(alpha);
  	element_random(theta);
  	element_random(xi);

  	element_mul(eeta, theta, xi);
  	element_add(eeta, eeta, rho);

	element_t hm, one;
	element_init_G1(hm, pairing);
	element_init_Zr(one, pairing)
	element_set1(one);

	element_pow3_zn(hm, gpk->g1, one, pubTPM, one, gpk->h2, memCre->rho);

	element_init_G1(sigma0->L, pairing);
  	element_pow2_zn(sigma0->L, pubTPM, one, gpk->h2, alpha);

	element_t temp, temp1;
	element_init_Zr(temp, pairing);
	element_init_Zr(temp1, pairing);
	element_init_G1(sigma0->U1, pairing);

	element_invert(temp, theta);
	element_pow_zn(sigma0->U1, memCre->J, temp);

  	element_neg(temp1, memCre->z);
	element_pow2_zn(sigma0->U2, memCre->J, temp1, hm, one);
  	element_pow_zn(sigma0->U2, sigma0->U2, temp);

  	element_pow2_zn(sigma0->U3, hm, temp, gpk->h2, xi);

	element_t ral, rz, rta, rxi, reta;
  	element_init_Zr(rz, pairing);
  	element_init_Zr(rta, pairing);
  	element_init_Zr(ral, pairing);
  	element_init_Zr(rxi, pairing);
  	element_init_Zr(reta, pairing);
  	element_random(rz);
  	element_random(rta);
  	element_random(ral);
  	element_random(rxi);
  	element_random(reta);

	element_t R1, R2, R3, R4;
	element_init_G1(R1, pairing);
	element_init_G1(R2, pairing);
	element_init_G1(R3, pairing);
	element_init_G1(R4, pairing);

  	element_mul(R1, S10, one);	
	element_pow2_zn(R2, S20, one, gpk->h2, ral);
  	element_pow2_zn(R3, sigma0->U1, rz, gpk->h2, rxi);
 	element_neg(temp, reta);
  	element_invert(temp1, S20);
  	element_pow3_zn(R4, sigma0->U3, rta, temp1, one, gpk->h2, temp);

	element_t ch0;
	element_init_Zr(ch0, pairing);
  	Hash2(ch0, Bj, sigma0->Kj, sigma0->L, sigma0->U1, sigma0->U2, sigma0->U3, R1, R2, R3, R4, 9);
  	//forward 'ch0' to TPM

	//TPM2_Sign algo
	//output : (sigma0->nt0, sigma0->ct0, sigma0->sfg)
	element_init_Zr(sigma0->ct0, pairing);
	element_init_Zr(sigma0->sfg, pairing);

  	element_init_Zr(sigma0->sz, pairing);
  	element_init_Zr(sigma0->sta, pairing);
  	element_init_Zr(sigma0->sal, pairing);
  	element_init_Zr(sigma0->sxi, pairing);
  	element_init_Zr(sigma0->seta, pairing);

	element_mul(sigma0->sal, sigma0->ct0, alpha);
	element_add(sigma0->sal, ral, sigma0->sal);
	element_mul(sigma0->sz, sigma0->ct0, memCre->z);
	element_add(sigma0->sz, rz, sigma0->sz);
	element_mul(sigma0->sta, sigma0->ct0, theta);
	element_add(sigma0->sta, rta, sigma0->sta);
	element_mul(sigma0->sxi, sigma0->ct0, xi);
	element_add(sigma0->sxi, rxi, sigma0->sxi);
	element_mul(sigma0->seta, sigma0->ct0, eeta);
	element_add(sigma0->seta, reta, sigma0->seta);

	element_clear(Bj);
	element_clear(alpha);
	element_clear(theta);
	element_clear(xi);
	element_clear(eeta);
	element_clear(hm);
	element_clear(one);
	element_clear(rz);
	element_clear(rta);
	element_clear(ral);
	element_clear(rxi);
	element_clear(reta);
	element_clear(R1);
	element_clear(R2);
	element_clear(R3);
	element_clear(R4);
	element_clear(ch0);

	return 0;
}

int getSignCredentialIssuer

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
	element_clear(gpk->chi);
	element_clear(gpk->omega);
	free(gpk);
	gpk = NULL;
	element_clear(memCre->J);
	element_clear(memCre->z);
	element_clear(memCre->rho);
	free(memCre);
	memCre = NULL;
	TPM_RC rc = flush_handles();
	if (rc != 0)
	{
		perror("flush_handles failed");
		exit(1);
	}
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
	if (err != 0)
	{
		exit(1);
	}

	// open urandom for generating random bytes
	fp = fopen("/dev/urandom", "r");

	// ISSUER sends nonce (nim)
	uint32_t nim;
	err = fread(&nim, 4, 1, fp);
	if (err != 1) {
		perror("read urandom failed");
		exit(1);
	}	

	uint32_t *ntm = malloc(sizeof(uint32_t));
	if (ntm == NULL)
	{
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
	rc = createMemKeyHost(gpk, nim, pubTPM, ntm, ctm, sfm);
	if (rc != 0)
	{
		perror("problem in createMemKeyHost");
		exit(1);
	}

	// and sends (nm, sigma-m) to Issuer. Issuer returns memCre
	struct membershipCredential * memCre = malloc(
				sizeof(struct membershipCredential));
	if (memCre == NULL)
	{
		perror("malloc failed");
		exit(1);
	}
	err = createMemKeyIssuer(gpk, issuerSecret, nim, pubTPM, 
			*ntm, ctm, sfm, memCre);
	if (err != 0)
	{
		perror("createMemKeyIssuer failed");
		exit(1);
	}

	// clean up after the initial material
	element_clear(ctm);
	element_clear(sfm);
	free(ntm);

	/* Membership credential obtained, next getSignCredential */
	
//Pranav mods

	struct signatureSigma0 * sigma0 = malloc(
				sizeof(struct signatureSigma0));
	if (sigma0 == NULL)
	{
		perror("malloc failed");
		exit(1);
	}
	err = provePF_Membership(pubTPM, gpk, memCre, sigma0);
	if (err != 0)
	{
		perror("provePF_Membership failed");
		exit(1);
	}
//ends

	// clear all the structures and key material, flush handles in TPM
	clearKeyMaterial(pubTPM, issuerSecret, gpk, memCre);	
	pairing_clear(pairing);
	fclose(fp);
	return 0;
		
	/*
	element_init_G1(hm, pairing);
	element_init_G1(hs, pairing);

	element_t hm, hs;
	element_t f, p, z, a1j, a2i;
	element_t Bj, D, E, I, J, Kj, L, U1, U2, U3, S10, S20;
	element_t delta, eeta, mu, alpha, theta, rho, xi, psi, v;
	element_t rd, rf, rta, rz, rxi, rmu, reta, ral, rvi, rpsi;
	element_t sd, sf, sta, sz, sxi, smu, seta, sal, svi, spsi;
	element_t tw1, c, ch, ct, cq, cj;
	element_t tmp1, tmp11, tmp2, tmp22, tmpt, tmpt2, tmpr, tmpc;
	element_t one;
	element_t T1, T2, T3, R1, R2, R3, R1t, R2t, R3t, R4, R4t, Rm, Rmb;

	element_t x[k], beta[k], y[k], A[k];

	element_t O[nr], Bi[nr], Ki[nr], tow[nr];
	element_t RI[nr], RII[nr], P[nr], S1[nr], S2[nr];
	element_t cp[nr], cpt[nr], cqt[nr], nn[nr];
	element_t st[nr], sp[nr], sv[nr], rt[nr], rp[nr];

	//element_init_Zr(nm, pairing); // supposed to be binary
	//element_init_Zr(nt, pairing); // supposed to be binary
	uint32_t nt;

	element_init_Zr(a1j, pairing);
	element_init_Zr(a2i, pairing);
	element_init_G1(Bj, pairing);
	element_init_G1(D, pairing);
	element_init_G1(E, pairing);
	element_init_G1(I, pairing);
	element_init_G1(J, pairing);
	element_init_G1(Kj, pairing);
	element_init_G1(L, pairing);
	element_init_G1(U1, pairing);
	element_init_G1(U2, pairing);
	element_init_G1(U3, pairing);
	element_init_G1(S10, pairing);
	element_init_G1(S20, pairing);

	element_init_G1(T1, pairing);
	element_init_G1(T2, pairing);
	element_init_G1(T3, pairing);

	element_init_G1(R1, pairing);
	element_init_G1(R1t, pairing);
	element_init_G1(Rm, pairing);
	element_init_G1(Rmb, pairing);
	element_init_G1(R2, pairing);
	element_init_G1(R2t, pairing);
	element_init_G1(R3, pairing);
	element_init_G1(R3t, pairing);
	element_init_G1(R4, pairing);
	element_init_G1(R4t, pairing);

	element_init_G1(tmp1, pairing);
	element_init_G1(tmp11, pairing);
	element_init_G2(tmp2, pairing);
	element_init_G2(tmp22, pairing);
	element_init_GT(tmpt, pairing);
	element_init_GT(tmpt2, pairing);
	element_init_Zr(tmpr, pairing);
	element_init_Zr(tmpc, pairing);

	element_init_Zr(f, pairing);
	element_init_Zr(p, pairing);
	element_init_Zr(z, pairing);

	element_init_Zr(delta, pairing);
	element_init_Zr(eeta, pairing);
	element_init_Zr(mu, pairing);
	element_init_Zr(alpha, pairing);
	element_init_Zr(theta, pairing);
	element_init_Zr(rho, pairing);
	element_init_Zr(xi, pairing);
	element_init_Zr(psi, pairing);
	element_init_Zr(v, pairing);

	element_init_Zr(rd, pairing);
	element_init_Zr(rf, pairing);
	element_init_Zr(rta, pairing);
	element_init_Zr(rz, pairing);
	element_init_Zr(rxi, pairing);
	element_init_Zr(reta, pairing);
	element_init_Zr(ral, pairing);
	element_init_Zr(rvi, pairing);
	element_init_Zr(rpsi, pairing);
	element_init_Zr(rmu, pairing);
	element_init_Zr(sd, pairing);
	element_init_Zr(sf, pairing);
	element_init_Zr(sta, pairing);
	element_init_Zr(sz, pairing);
	element_init_Zr(sxi, pairing);
	element_init_Zr(seta, pairing);
	element_init_Zr(sal, pairing);
	element_init_Zr(svi, pairing);
	element_init_Zr(spsi, pairing);
	element_init_Zr(smu, pairing);

	element_init_Zr(c, pairing);
	element_init_Zr(cj, pairing);
	element_init_Zr(ct, pairing);
	element_init_Zr(cq, pairing);
	element_init_Zr(one, pairing);
	element_init_Zr(tw1, pairing);

	element_set1(one);

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
		// send (a2i, Bi[i]->y, Bj) to the TPM

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
		element_pow_zn(S2[i], Bj, rp[i]);
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
		element_pow2_zn(RII[i], S2[i], tow[i], Kj, tmpr);

		element_init_Zr(cp[i], pairing);
		Hash2(cp[i], Bj, Kj, Bi[i], Ki[i], P[i], RI[i], RII[i], 0, 0, 0,
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

	// compute (Bj->y) and set 'Bj'

	element_neg(tmpc, ct);
	element_pow2_zn(R1t, Bj, sf, Kj, tmpc);
	element_pow3_zn(R2t, h1, sf, h2, sal, L, tmpc);

	element_neg(tmpr, ct);
	element_pow2_zn(tmp1, U2, ct, U3, tmpr);
	element_pow3_zn(R3t, U1, sz, h2, sxi, tmp1, one);

	element_neg(tmpc, seta);
	element_pow2_zn(tmp1, h2, tmpc, g1, tmpr);
	element_neg(tmpc, sf);
	element_pow3_zn(R4t, U3, sta, h1, tmpc, tmp1, one);

	Hash2(cj, Bj, Kj, L, U1, U2, U3, R1t, R2t, R3t, R4t, 9);

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
		element_pow2_zn(RII[i], Bj, sv[i], Kj, tmpr);

		Hash2(cp[i], Bj, Kj, Bi[i], Ki[i], P[i], RI[i], RII[i], 0, 0, 0,
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

	// append tuple (a2j, Bj->y, Kj, x[0], ..., x[k-1], beta[0], ...,
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
	host = host + (t1 - t0);

	char *M = "Lucifer";

	// TPM again
	// NOAH************************************************
	t0 = pbc_get_time();
	element_random(nt);
	memset(ibuf, 0, sizeof ibuf);
	memset(jbuf, 0, sizeof jbuf);
	j = element_to_bytes(ibuf, ch);
	j = element_to_bytes(jbuf, nt);
	memcpy(ibuf + lz, jbuf, lz);
	memcpy(ibuf + 2 * lz, M, strlen(M));
	SHA256(ibuf, strlen((char *)ibuf), obuf);
	element_from_hash(ct, obuf, 32);

	element_mul(sf, ct, f);
	element_add(sf, rf, sf);
	// send (ct, nt, sf) to Host

	t1 = pbc_get_time();
	tpm = tpm + (t1 - t0);

	// HOST
	t0 = pbc_get_time();

	element_mul(sd, ct, delta);
	element_add(sd, rd, sd);
	element_mul(smu, ct, mu);
	element_add(smu, rmu, smu);
	element_mul(svi, ct, v);
	element_add(svi, rvi, svi);
	element_mul(spsi, ct, psi);
	element_add(spsi, rpsi, spsi);

	// signature sigma-s = (x[r], t2, D->y, E, T1, T2, T3, nt, ct, sf, sd,
	// smu, svi, spsi)

	t1 = pbc_get_time();
	host = host + (t1 - t0);

	printf("\tTPM, time elapsed %.2fms\n", tpm * 1000);
	printf("\tHost, time elapsed %.2fms\n\n", host * 1000);

	tpm = 0;
	host = 0;
	iss = 0;

	// Verify -----------------------------------------------------------
	t0 = pbc_get_time();

	element_pairing(tmpt, T1, omega);
	element_pairing(tmpt2, T2, g2);
	if (element_cmp(tmpt, tmpt2))
		printf("\n Verifier 1(b) pairing comparison not passed! :O \n");

	element_neg(tmpr, ct);
	element_pow2_zn(R1t, D, sf, E, tmpr);

	element_neg(tmpc, spsi);
	element_pow2_zn(R2t, g1, x[r], chi, one);
	element_pow2_zn(R2t, R2t, tmpc, h2, smu);
	element_invert(tmp11, T3);
	element_pow3_zn(tmp1, T1, x[r], T2, one, tmp11, one);
	element_pow2_zn(R2t, R2t, one, tmp1, ct);

	element_neg(tmpc, svi);
	element_pow2_zn(R3t, h2, tmpc, g1, tmpr);
	element_neg(tmpc, sf);
	element_pow3_zn(R3t, T3, sd, h1, tmpc, R3t, one);

	Hash2(cj, D, E, T1, T2, T3, R1t, R2t, R3t, x[r], 0, 8);

	memset(ibuf, 0, sizeof ibuf);
	memset(jbuf, 0, sizeof jbuf);
	j = element_to_bytes(ibuf, cj);
	j = element_to_bytes(jbuf, nt);
	memcpy(ibuf + lz, jbuf, lz);
	memcpy(ibuf + 2 * lz, M, strlen(M));
	SHA256(ibuf, strlen((char *)ibuf), obuf);
	element_from_hash(cq, obuf, 32);

	if (element_cmp(ct, cq))
		printf("Verifier verification not passed for c! -_- \n");

	t1 = pbc_get_time();
	printf("Verifying the signature, time elapsed %.2fms\n\n",
	       (t1 - t0) * 1000);

	// check for x[k] in atRL	-	Rev.c
	// valid or invalid

	// Revoke -------------------------------------

	fclose(fp);

	for (i = 0; i < nr; i++) {
		element_clear(Bi[i]);
		element_clear(O[i]);
		element_clear(S1[i]);
		element_clear(S2[i]);
		element_clear(Ki[i]);
		element_clear(P[i]);
		element_clear(RI[i]);
		element_clear(RII[i]);
		element_clear(nn[i]);
		element_clear(rp[i]);
		element_clear(tow[i]);
		element_clear(rt[i]);
		element_clear(cp[i]);
		element_clear(sp[i]);
		element_clear(cpt[i]);
		element_clear(cqt[i]);
		element_clear(st[i]);
		element_clear(sv[i]);
	}

	for (i = 0; i < k; i++) {
		element_clear(y[i]);
		element_clear(x[i]);
		element_clear(A[i]);
		element_clear(beta[i]);
	}

	element_clear(g1);
	element_clear(g2);
	element_clear(h1);
	element_clear(h2);
	element_clear(hm);
	element_clear(hs);
	element_clear(gamma);
	element_clear(chi);
	element_clear(omega);
	element_clear(nm);
	element_clear(nt);
	element_clear(Rm);
	element_clear(Rmb);
	element_clear(Bj);
	element_clear(Kj);
	element_clear(I);
	element_clear(J);
	element_clear(D);
	element_clear(E);
	element_clear(L);
	element_clear(U1);
	element_clear(U2);
	element_clear(U3);
	element_clear(T1);
	element_clear(T2);
	element_clear(T3);
	element_clear(S10);
	element_clear(S20);
	element_clear(R1);
	element_clear(R1t);
	element_clear(R2);
	element_clear(R2t);
	element_clear(R3);
	element_clear(R3t);
	element_clear(R4);
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

