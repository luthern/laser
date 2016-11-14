#include "laser_tpm.h"
#include "laser_utils.h"

int main(int argc, char *argv[])
{
	if (argc < 5) {
		printf("Usage: laser_platform paramfile hostname"
			" num_alias_tokens revoked_sig_cnt\n");
	}
	int iterations;
	if (argc == 5) {
		iterations = 1;
	}
	else {
		iterations = (int) strtol(argv[5], NULL, 10);
	}
	srand(time(NULL));
	unsigned int r = rand();

	pairing_t pairing;
	element_t g1, g2, h1, h2, h3;
	element_t gamma;
	element_t cnt, PI, DAAseed, bsn, bsnn;
	element_t f, p, z;
	element_t D, E, I, J, K1, K2, S10, S20;
	element_t delta, eeta, mu, mu1, mu2, rho, xi;
	element_t rd, rf, rrho, rz, rxi, reta, rmu;
	element_t sd, sf, srho, sz, sxi, seta, smu;
	element_t c, ct, cq;
	element_t tmp1, tmp11, tmp2, tmp22, tmpt, tmpt2, tmpr, tmpc;
	element_t index;
	element_t T1, R1, R2, R3, R1t, R2t, R3t, R4, R4t;
	element_t one;
	element_pp_t gp1, gp2;

	double gmk_tpm = 0;
	double gmk_host = 0;
	double gsk_tpm = 0;
	double gsk_host = 0;
	double sign_tpm = 0;
	double sign_host = 0;
	double verify = 0;
	double epid_sign = 0;
	int i;
	int k = (int) strtol(argv[3], NULL, 10);  // # alias tokens
	int nr = (int) strtol(argv[4], NULL, 10); // # number revoked users
	printf("Number of Alias Tokens: %d\n", k);
	printf("Number of Revoked Basenames: %d\n", nr);
	//printf("Number of Iterations: %d\n", iterations);
	int key_size1;
	int key_size2;
	int key_sizezp;
	element_t w[k];
	element_t x[k];

	element_t F[nr];
	element_t Dn[nr];
	element_t En[nr];
	element_t tow[nr];
	element_t RI[nr];
	element_t RII[nr];
	element_t P[nr];
	element_t S1[nr];
	element_t S2[nr];
	unsigned char cp[nr][32];
	element_t cpt[nr];
	element_t st[nr];
	element_t sp[nr];
	element_t sv[nr];
	element_t rt[nr];
	uint32_t nn[nr];

	element_t A[k];
	element_pp_t wp[k];

	double t0 = 0;
	double t1 = 0;
	double *time_taken = malloc(sizeof(double));
	double tpm = 0;
	double host = 0;
	unsigned char ibuf[2500];
	unsigned char jbuf[500];
	unsigned char obuf[32];

	pbc_demo_pairing_init(pairing, argc, argv);

	element_init_G1(g1, pairing);
	element_init_G2(g2, pairing);

	element_init_G1(h1, pairing);
	element_init_G1(h2, pairing);
	element_init_G1(h3, pairing);
	element_init_Zr(gamma, pairing);

	element_init_Zr(cnt, pairing);
	element_init_Zr(PI, pairing);
	element_init_Zr(DAAseed, pairing);
	element_init_Zr(bsn, pairing);
	element_init_Zr(bsnn, pairing);

	element_init_G1(D, pairing);
	element_init_G1(E, pairing);
	element_init_G1(I, pairing);
	element_init_G1(J, pairing);
	element_init_G1(K1, pairing);
	element_init_G1(K2, pairing);
	element_init_G1(S10, pairing);
	element_init_G1(S20, pairing);

	element_init_G1(T1, pairing);

	element_init_G1(R1, pairing);
	element_init_G1(R1t, pairing);
	element_init_G1(R2, pairing);
	element_init_G1(R2t, pairing);
	element_init_G1(R3, pairing);
	element_init_G1(R3t, pairing);
	element_init_GT(R4, pairing);
	element_init_GT(R4t, pairing);

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
	element_init_Zr(mu1, pairing);
	element_init_Zr(mu2, pairing);
	element_init_Zr(rho, pairing);
	element_init_Zr(xi, pairing);

	element_init_Zr(rd, pairing);
	element_init_Zr(rf, pairing);
	element_init_Zr(rrho, pairing);
	element_init_Zr(rz, pairing);
	element_init_Zr(rxi, pairing);
	element_init_Zr(reta, pairing);
	element_init_Zr(rmu, pairing);
	element_init_Zr(sd, pairing);
	element_init_Zr(sf, pairing);
	element_init_Zr(srho, pairing);
	element_init_Zr(sz, pairing);
	element_init_Zr(sxi, pairing);
	element_init_Zr(seta, pairing);
	element_init_Zr(smu, pairing);

	element_init_Zr(c, pairing);
	element_init_Zr(ct, pairing);
	element_init_Zr(cq, pairing);
	element_init_Zr(one, pairing);
	element_init_Zr(index, pairing);

	element_set1(one);

	//printf("\t----- LASER scheme -----\n\n");

	struct sockaddr_in server_info;
	struct hostent *he;
	int socket_fd, num;
	char buffer[MAXSIZE];

	if ((he = gethostbyname(argv[2])) == NULL) {
		fprintf(stderr, "Cannot get host name\n");
		exit(1);
	}

	if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		fprintf(stderr, "Socket Failure!!\n");
		exit(1);
	}

	memset(&server_info, 0, sizeof(server_info));
	server_info.sin_family = AF_INET;
	server_info.sin_port = htons(PORT);
	server_info.sin_addr = *((struct in_addr *)he->h_addr);
	if (connect(socket_fd, (struct sockaddr *)&server_info,
		    sizeof(struct sockaddr)) < 0) {
		perror("connect");
		exit(1);
	}

	unsigned char *write_data1, *write_datazp;

	element_random(g1);
	element_random(g2);
	element_random(ct);
	key_size1 = element_length_in_bytes_compressed(g1);
	key_size2 = element_length_in_bytes_compressed(g2);
	key_sizezp = element_length_in_bytes(ct);
	write_data1 = pbc_malloc(key_size1);
	write_datazp = pbc_malloc(key_sizezp);

	uint32_t bytes_written = 0;
	uint32_t current_offset = 0;
	uint32_t nm = 0;
	uint32_t nmm = 0;
	int err;
	FILE *fp;
	fp = fopen("/dev/urandom", "r");

	TPM_RC rc = 0;

	int it_counter = 0;
	while (it_counter < iterations) {
		it_counter++;
		rc = initTPM();
		if (rc != 0) {
			perror("initTPM failed");
			exit(1);
		}

		// KeyGen recv data
		memset(buffer, 0, sizeof(buffer));
		num = recv(socket_fd, buffer, key_size1, 0);
		if (num <= 0) {
			printf("Either Connection Closed or Error\n");
			break;
		}
		element_from_bytes_compressed(h1,
					      (unsigned char *)buffer);

		memset(buffer, 0, sizeof(buffer));
		num = recv(socket_fd, buffer, key_size1, 0);
		if (num <= 0) {
			printf("Either Connection Closed or Error\n");
			break;
		}
		element_from_bytes_compressed(h2,
					      (unsigned char *)buffer);

		memset(buffer, 0, sizeof(buffer));
		num = recv(socket_fd, buffer, key_size1, 0);
		if (num <= 0) {
			printf("Either Connection Closed or Error\n");
			break;
		}
		element_from_bytes_compressed(g1,
					      (unsigned char *)buffer);

		memset(buffer, 0, sizeof(buffer));
		num = recv(socket_fd, buffer, key_size2, 0);
		if (num <= 0) {
			printf("Either Connection Closed or Error\n");
			break;
		}
		element_from_bytes_compressed(g2,
					      (unsigned char *)buffer);

		memset(buffer, 0, sizeof(buffer));
		num = recv(socket_fd, buffer, key_size1, 0);
		if (num <= 0) {
			printf("Either Connection Closed or Error\n");
			break;
		}
		element_from_bytes_compressed(h3,
					      (unsigned char *)buffer);

		for (i = 0; i < k; i++) { // k is 'ma'
			element_init_G2(w[i], pairing);

			memset(buffer, 0, sizeof(buffer));
			num = recv(socket_fd, buffer, key_size2, 0);
			if (num <= 0) {
				printf("Either Connection Closed or "
				       "Error\n");
				break;
			}
			element_from_bytes_compressed(w[i], 
						(unsigned char *)buffer);
			element_pp_init(wp[i], w[i]);
		}

		element_pp_init(gp1, g1);
		element_pp_init(gp2, g2);

		//printf("\nKeyGen done!\n\n");

		if ((send(socket_fd, buffer, strlen(buffer), 0)) ==
		    -1) {
			fprintf(stderr, "Failure Sending Message\n");
			close(socket_fd);
			exit(1);
		}

		// GetMemKey
		//printf("GetMemKey :\n");

		// recv nonce

		memset(buffer, 0, sizeof(buffer));
		num = recv(socket_fd, &nm, 4, 0);
		if (num <= 0) {
			printf("Either Connection Closed or Error\n");
			break;
		}

		// HOST

		//******************************************START
		// TPM operations

		//t0 = pbc_get_time();
		unsigned char I_x[32];
		unsigned char I_y[32];
		rc = createMemKeyP1(I_x, I_y, time_taken);
		if (rc != 0) {
			perror("createMemKeyP1 failed");
			exit(1);
		}
		tpm += *time_taken;
		unsigned char I_buf[64];
		memcpy(I_buf, I_x, 32);
		memcpy(I_buf + 32, I_y, 32);
		element_from_bytes(I, I_buf);

		unsigned char h1_x[32] = { 0x00 };
		unsigned char h1_y[32] = { 0x00 };
		h1_x[31] = 0x01;
		h1_y[31] = 0x02;
		unsigned char Rm_x[32];
		unsigned char Rm_y[32];
		uint16_t *commit_cntr = malloc(sizeof(uint16_t));
		if (commit_cntr == NULL) {
			perror("malloc failed");
			exit(1);
		}
		rc = createMemKeyP2(h1_x, h1_y, Rm_x, Rm_y, commit_cntr, time_taken);
		if (rc != 0) {
			perror("createMemKeyP2 failed");
			exit(1);
		}
		unsigned char Rm_buf[64];
		memcpy(Rm_buf, Rm_x, 32);
		memcpy(Rm_buf + 32, Rm_y, 32);
		element_from_bytes(R1, Rm_buf);

		//t1 = pbc_get_time();
		tpm += *time_taken;

		//*******************************************END
		// HOST here
		t0 = pbc_get_time();

		current_offset = 0;
		memset(ibuf, 0, sizeof(ibuf));
		memset(jbuf, 0, sizeof(jbuf));
		memcpy(ibuf, &nm, 4);
		current_offset += 4;
		bytes_written = element_to_bytes(jbuf, I);
		memcpy(ibuf + current_offset, jbuf, bytes_written);
		current_offset += bytes_written;
		bytes_written = element_to_bytes(jbuf, R1);
		memcpy(ibuf + current_offset, jbuf, bytes_written);
		current_offset += bytes_written;
		SHA256(ibuf, current_offset, obuf);
		current_offset = 0;
		element_from_hash(ct, obuf, 32);
		// forward 'ct' to TPM

		t1 = pbc_get_time();
		host = host + (t1 - t0);
		//*******************************************START
		//t0 = pbc_get_time();
		// For now generate nonce on host, TODO do on TPM
		err = fread(&nmm, 4, 1, fp); // read 4 bytes /dev/urandom
		if (err != 1) {
			perror("read urandom failed");
			exit(1);
		}

		// TPM now in action
		unsigned char c_buf[32];
		unsigned char sf_buf[32];
		unsigned char ct_buf[32];
		element_to_bytes(ct_buf, ct);
		rc = createMemKeyP3(nmm, *commit_cntr, ct_buf, c_buf, sf_buf, time_taken);
		if (rc != 0) {
			perror("createMemKeyP3 failed");
			exit(1);
		}
		element_from_bytes(c, c_buf);
		element_from_bytes(sf, sf_buf);
		free(commit_cntr);

		//t1 = pbc_get_time();
		tpm += *time_taken;
		
		//*******************************************END

		// HOST sends (nm, nmm, sig-m) to the issuer

		element_to_bytes_compressed(write_data1, I);

		if ((send(socket_fd, write_data1, key_size1, 0)) ==
		    -1) {
			fprintf(stderr, "Failure Sending Message\n");
			close(socket_fd);
			break;
		}

		if ((send(socket_fd, &nm, 4, 0)) ==
		    -1) {
			fprintf(stderr, "Failure Sending Message\n");
			close(socket_fd);
			break;
		}

		if ((send(socket_fd, &nmm, 4, 0)) ==
		    -1) {
			fprintf(stderr, "Failure Sending Message\n");
			close(socket_fd);
			break;
		}

		element_to_bytes(write_datazp, c);

		if ((send(socket_fd, write_datazp, key_sizezp, 0)) ==
		    -1) {
			fprintf(stderr, "Failure Sending Message\n");
			close(socket_fd);
			break;
		}

		element_to_bytes(write_datazp, sf);

		if ((send(socket_fd, write_datazp, key_sizezp, 0)) ==
		    -1) {
			fprintf(stderr, "Failure Sending Message\n");
			close(socket_fd);
			break;
		}

		// Issuer recv, compute, send

		memset(buffer, 0, sizeof(buffer));
		num = recv(socket_fd, buffer, key_size1, 0);
		if (num <= 0) {
			printf("Either Connection Closed or Error\n");
			break;
		}
		element_from_bytes_compressed(J, (unsigned char *) buffer);

		memset(buffer, 0, sizeof(buffer));
		num = recv(socket_fd, buffer, key_sizezp, 0);
		if (num <= 0) {
			printf("Either Connection Closed or Error\n");
			break;
		}
		element_from_bytes(z, (unsigned char *) buffer);

		memset(buffer, 0, sizeof(buffer)); // namma add
		num = recv(socket_fd, buffer, key_sizezp, 0);
		if (num <= 0) {
			printf("Either Connection Closed or Error\n");
			break;
		}
		element_from_bytes(rho, (unsigned char *) buffer);

		// HOST side

		t0 = pbc_get_time();

		element_pow_zn(tmp2, g2, z);
		element_mul(tmp2, w[0], tmp2);
		element_pairing(tmpt, J, tmp2);
		element_pow_zn(tmp11, h2, rho);
		element_mul(tmp1, g1, I);
		element_mul(tmp1, tmp1, tmp11);
		element_pairing(tmpt2, tmp1, g2);

		if (element_cmp(tmpt, tmpt2))
			printf("GetMemKey 7(a) verification not "
			       "passed! :(\n");
		// output Host credentials creMEM = (J, z, rho)

		t1 = pbc_get_time();
		host = host + (t1 - t0);
		gmk_host += host;
		gmk_tpm += tpm;
		//printf("\tTPM, time elapsed %.2fms\n", tpm * 1000);
		//printf("\tHost, time elapsed %.2fms\n", host * 1000);

		tpm = 0;
		host = 0;

		// GetSignKey -----------------------------------
		//printf("GetSignKey :\n");

		t0 = pbc_get_time();

		// HOST side
		generate_x_check_ecc(D, bsn);
		t1 = pbc_get_time();
		host = host + (t1 - t0);

		//*******************************************START
		// TPM performs

		//t0 = pbc_get_time();
		unsigned char bj[32];
		unsigned char d2j[32];
		element_to_bytes(bj, bsn);
		
		// produce the x component now as well
		// we need this later
		unsigned char D_x[32];
		element_to_bytes(D_x, element_x(D));
		element_to_bytes(d2j, element_y(D));	

		unsigned char Ej_x[32];
		unsigned char Ej_y[32];
		unsigned char S10_x[32];
		unsigned char S10_y[32];
		unsigned char S20_x[32];
		unsigned char S20_y[32];
		commit_cntr = malloc(sizeof(uint16_t));

		rc = getSignKeyP1(h1_x, h1_y, bj, d2j,
				Ej_x, Ej_y, S10_x, S10_y,
				S20_x, S20_y, commit_cntr,
				time_taken);
		if (rc != 0) {
			perror("getSignKeyP1 failed");
			exit(1);
		}
		unsigned char Ej_buf[64];
		memcpy(Ej_buf, Ej_x, 32);
		memcpy(Ej_buf + 32, Ej_y, 32);
		element_from_bytes(E, Ej_buf);
		unsigned char S10_buf[64];
		memcpy(S10_buf, S10_x, 32);
		memcpy(S10_buf + 32, S10_y, 32);
		element_from_bytes(S10, S10_buf);
		unsigned char S20_buf[64];
		memcpy(S20_buf, S20_x, 32);
		memcpy(S20_buf + 32, S20_y, 32);
		element_from_bytes(S20, S20_buf);
		// send (E, S10, S20) to Host

		//t1 = pbc_get_time();
		tpm += *time_taken;

		//*******************************************END
		// HOST does

		t0 = pbc_get_time();

		element_random(mu1);
		element_random(xi);
		element_mul(eeta, xi, z);
		element_pow2_zn(K1, I, one, h2, mu1);
		element_pow2_zn(K2, J, one, h3, xi);

		element_random(rz);
		element_random(rrho);
		element_random(rmu);
		element_random(rxi);
		element_random(reta);

		element_mul(R1, S10, one);
		element_pow2_zn(R2, S20, one, h2, rmu);
		element_neg(tmpr, rz);
		element_pow3_zn(tmp1, K2, tmpr, S20, one, h2, rrho);
		element_pow2_zn(tmp1, tmp1, one, h3, reta);
		element_pairing(tmpt, tmp1, g2);
		element_pairing(tmpt2, h3, w[0]);
		element_pow_zn(tmpt2, tmpt2, rxi);
		element_mul(R3, tmpt, tmpt2);

		memset(ibuf, 0, sizeof(ibuf));
		memset(jbuf, 0, sizeof(jbuf));
		current_offset = element_to_bytes(ibuf, D);
		bytes_written = element_to_bytes(jbuf, E);
		memcpy(ibuf + current_offset, jbuf, bytes_written);
		
		current_offset += bytes_written;
		bytes_written = element_to_bytes(jbuf, K1);
		memcpy(ibuf + current_offset, jbuf, bytes_written);
		
		current_offset += bytes_written;
		bytes_written = element_to_bytes(jbuf, K2);
		memcpy(ibuf + current_offset, jbuf, bytes_written);
		
		current_offset += bytes_written;
		bytes_written = element_to_bytes(jbuf, R1);
		memcpy(ibuf + current_offset, jbuf, bytes_written);
		
		current_offset += bytes_written;
		bytes_written = element_to_bytes(jbuf, R2);
		memcpy(ibuf + current_offset, jbuf, bytes_written);
		
		current_offset += bytes_written;
		bytes_written = element_to_bytes(jbuf, R3);
		memcpy(ibuf + current_offset, jbuf, bytes_written);
		
		current_offset += bytes_written;
		SHA256(ibuf, current_offset, obuf);
		element_from_hash(c, obuf, 32);
		current_offset = 0;
		// forward 'c' to TPM

		t1 = pbc_get_time();
		host = host + (t1 - t0);

		//*******************************************START
		unsigned char chi[32];
		element_to_bytes(chi, c);

		// TPM in action
		//t0 = pbc_get_time();

		err = fread(&nm, 4, 1, fp); // read 4 bytes /dev/urandom
		if (err != 1) {
			perror("read urandom failed");
			exit(1);
		}
		// send (ct, nm, sf) to Host

		unsigned char cg0[32];
		unsigned char sfg[32];
		rc = getSignKeyP2(*commit_cntr, nm, chi, cg0, sfg, time_taken); 
		if (rc != 0) {
			perror("getSignKeyP2 failed");
			exit(1);
		}
		element_from_bytes(ct, cg0);
		element_from_bytes(sf, sfg);
		free(commit_cntr);
		//t1 = pbc_get_time();
		tpm += *time_taken;

		//*******************************************END
		// HOST back to work

		t0 = pbc_get_time();

		element_mul(smu, ct, mu1);
		element_add(smu, rmu, smu);
		element_mul(sz, ct, z);
		element_add(sz, rz, sz);
		element_mul(srho, ct, rho);
		element_add(srho, rrho, srho);
		element_mul(sxi, ct, xi);
		element_add(sxi, rxi, sxi);
		element_mul(seta, ct, eeta);
		element_add(seta, reta, seta);
		// output signature 'sig-0' = (bsn, D->y, E, K1, K2, ct,
		// sf, smu, sz, sxi,
		// seta, srho)

		t1 = pbc_get_time();
		host = host + (t1 - t0);

		for (i = 0; i < nr; i++) { // nr = baseRL
			// HOST
			t0 = pbc_get_time();
			element_init_G1(Dn[i], pairing);
			generate_x_check_ecc(Dn[i], bsnn);
			t1 = pbc_get_time();
			host = host + (t1 - t0);
			// send (bsnn, Dn[i]->y, D) to the TPM

			//*******************************************START
			unsigned char bi[32];
			unsigned char d2i[32];
			element_to_bytes(bi, bsnn);
			element_to_bytes(d2i, element_y(Dn[i]));
			
			// TPM performs
			//t0 = pbc_get_time();
			element_init_G1(F[i], pairing);
			element_init_G1(S1[i], pairing);
			element_init_G1(S2[i], pairing);
			
			unsigned char Oi_x[32];
			unsigned char Oi_y[32];
			unsigned char S1i_x[32];
			unsigned char S1i_y[32];
			unsigned char S2i_x[32];
			unsigned char S2i_y[32];
			commit_cntr = malloc(sizeof(uint16_t));
			// D_x is the SHA256 of earlier bj
			// d2j is the y element of D from earlier
			// these should be the right x and y of D.
			rc = getSignKeyP3(D_x, d2j, bi, d2i, 
					Oi_x, Oi_y, S1i_x, S1i_y, 
					S2i_x, S2i_y, commit_cntr, time_taken);
			if (rc != 0) {
				perror("getSignKeyP3 failed");
				exit(1);
			}
			unsigned char Fi_buf[64];
			memcpy(Fi_buf, Oi_x, 32);
			memcpy(Fi_buf + 32, Oi_y, 32);
			element_from_bytes(F[i], Fi_buf);

			unsigned char S1i_buf[64];
			memcpy(S1i_buf, S1i_x, 32);
			memcpy(S1i_buf + 32, S1i_y, 32);
			element_from_bytes(S1[i], S1i_buf);

			unsigned char S2i_buf[64];
			memcpy(S2i_buf, S2i_x, 32);
			memcpy(S2i_buf + 32, S2i_y, 32);
			element_from_bytes(S2[i], S2i_buf);
			//t1 = pbc_get_time();
			tpm += *time_taken;

			//*******************************************END

			// HOST now
			t0 = pbc_get_time();
			element_init_Zr(tow[i], pairing);
			element_init_G1(En[i], pairing);
			element_random(tow[i]);
			element_random(En[i]);
			element_invert(En[i], En[i]);
			element_init_G1(P[i], pairing);
			element_mul(P[i], F[i], En[i]);
			element_pow_zn(P[i], P[i], tow[i]);

			if (!element_cmp(P[i], one))
				printf("GetSignKey 2.c.ii verification "
				       "not passed! :/\n");

			element_invert(En[i], En[i]);
			element_init_Zr(rt[i], pairing);
			element_random(rt[i]);
			element_init_G1(RI[i], pairing);
			element_init_G1(RII[i], pairing);
			element_neg(tmpr, rt[i]);
			element_pow2_zn(RI[i], S1[i], tow[i], En[i],
					tmpr);

			element_pow2_zn(RII[i], S2[i], tow[i], E, tmpr);

			memset(ibuf, 0, sizeof(ibuf));
			memset(jbuf, 0, sizeof(jbuf));
			current_offset = element_to_bytes(ibuf, D);
			bytes_written = element_to_bytes(jbuf, E);
			memcpy(ibuf + current_offset, jbuf, bytes_written);

			current_offset += bytes_written;
			bytes_written = element_to_bytes(jbuf, Dn[i]);
			memcpy(ibuf + current_offset, jbuf, bytes_written);
			
			current_offset += bytes_written;
			bytes_written = element_to_bytes(jbuf, En[i]);
			memcpy(ibuf + current_offset, jbuf, bytes_written);
			
			current_offset += bytes_written;
			bytes_written = element_to_bytes(jbuf, P[i]);
			memcpy(ibuf + current_offset, jbuf, bytes_written);
			
			current_offset += bytes_written;
			bytes_written = element_to_bytes(jbuf, RI[i]);
			memcpy(ibuf + current_offset, jbuf, bytes_written);

			current_offset += bytes_written;
			bytes_written = element_to_bytes(jbuf, RII[i]);
			memcpy(ibuf + current_offset, jbuf, bytes_written);

			current_offset += bytes_written;
			SHA256(ibuf, current_offset, cp[i]);
			// send 'cp[i]' to TPM
			t1 = pbc_get_time();
			host = host + (t1 - t0);

			//*******************************************START
			//t0 = pbc_get_time();
			
			element_init_Zr(sp[i], pairing);
			element_init_Zr(cpt[i], pairing);
			err = fread(&nn[i], 4, 1, fp);
			if (err != 1) {
				perror("read urandom failed");
				exit(1);
			}

			unsigned char cgi[32];
			unsigned char sfi[32];
			rc = getSignKeyP4(*commit_cntr, nn[i], cp[i],
					cgi, sfi, time_taken);
			if (rc != 0) {
				perror("getSignKeyP4 failed");
				exit(1);
			}
			element_from_bytes(cpt[i], cgi);
			element_from_bytes(sp[i], sfi);
			free(commit_cntr);

			t1 = pbc_get_time();
			tpm += *time_taken;

			//*******************************************END

			// HOSTtttttt
			t0 = pbc_get_time();
			element_init_Zr(st[i], pairing);
			element_mul(st[i], cpt[i], tow[i]);
			element_add(st[i], rt[i], st[i]);
			element_init_Zr(sv[i], pairing);
			element_mul(sv[i], sp[i], tow[i]);
			// output the signature 'sigma-i = (P[i],
			// cpt[i], st[i], sv[i])'

			// Host sends (nm, sig-0, nn[0], sig[0],...,
			// nn[nr], sig[nr]) to Issuer
			t1 = pbc_get_time();
			host = host + (t1 - t0);
		}

		// GetSignKey - send to Issuer

		if ((send(socket_fd, &nm, 4, 0)) ==
		    -1) {
			fprintf(stderr, "Failure Sending Message\n");
			close(socket_fd);
			break;
		}

		element_to_bytes_compressed(write_data1,
					    D); // send bsn and D->y

		if ((send(socket_fd, write_data1, key_size1, 0)) ==
		    -1) {
			fprintf(stderr, "Failure Sending Message\n");
			close(socket_fd);
			break;
		}

		element_to_bytes_compressed(write_data1, E);

		if ((send(socket_fd, write_data1, key_size1, 0)) ==
		    -1) {
			fprintf(stderr, "Failure Sending Message\n");
			close(socket_fd);
			break;
		}

		element_to_bytes_compressed(write_data1, K1);

		if ((send(socket_fd, write_data1, key_size1, 0)) ==
		    -1) {
			fprintf(stderr, "Failure Sending Message\n");
			close(socket_fd);
			break;
		}

		element_to_bytes_compressed(write_data1, K2);

		if ((send(socket_fd, write_data1, key_size1, 0)) ==
		    -1) {
			fprintf(stderr, "Failure Sending Message\n");
			close(socket_fd);
			break;
		}

		element_to_bytes(write_datazp, ct);

		if ((send(socket_fd, write_datazp, key_sizezp, 0)) ==
		    -1) {
			fprintf(stderr, "Failure Sending Message\n");
			close(socket_fd);
			break;
		}

		element_to_bytes(write_datazp, sf);

		if ((send(socket_fd, write_datazp, key_sizezp, 0)) ==
		    -1) {
			fprintf(stderr, "Failure Sending Message\n");
			close(socket_fd);
			break;
		}

		element_to_bytes(write_datazp, smu);

		if ((send(socket_fd, write_datazp, key_sizezp, 0)) ==
		    -1) {
			fprintf(stderr, "Failure Sending Message\n");
			close(socket_fd);
			break;
		}

		element_to_bytes(write_datazp, sz);

		if ((send(socket_fd, write_datazp, key_sizezp, 0)) ==
		    -1) {
			fprintf(stderr, "Failure Sending Message\n");
			close(socket_fd);
			break;
		}

		element_to_bytes(write_datazp, sxi);

		if ((send(socket_fd, write_datazp, key_sizezp, 0)) ==
		    -1) {
			fprintf(stderr, "Failure Sending Message\n");
			close(socket_fd);
			break;
		}

		element_to_bytes(write_datazp, seta);

		if ((send(socket_fd, write_datazp, key_sizezp, 0)) ==
		    -1) {
			fprintf(stderr, "Failure Sending Message\n");
			close(socket_fd);
			break;
		}

		element_to_bytes(write_datazp, srho);

		if ((send(socket_fd, write_datazp, key_sizezp, 0)) ==
		    -1) {
			fprintf(stderr, "Failure Sending Message\n");
			close(socket_fd);
			break;
		}

		for (i = 0; i < nr; i++) // nr = baseRL
		{
			if ((send(socket_fd, &nn[i], 4,
				  0)) == -1) {
				fprintf(stderr,
					"Failure Sending Message\n");
				close(socket_fd);
				break;
			}

			element_to_bytes_compressed(write_data1, P[i]);

			if ((send(socket_fd, write_data1, key_size1,
				  0)) == -1) {
				fprintf(stderr,
					"Failure Sending Message\n");
				close(socket_fd);
				break;
			}

			element_to_bytes(write_datazp, cpt[i]);

			if ((send(socket_fd, write_datazp, key_sizezp,
				  0)) == -1) {
				fprintf(stderr,
					"Failure Sending Message\n");
				close(socket_fd);
				break;
			}

			element_to_bytes(write_datazp, st[i]);

			if ((send(socket_fd, write_datazp, key_sizezp,
				  0)) == -1) {
				fprintf(stderr,
					"Failure Sending Message\n");
				close(socket_fd);
				break;
			}

			element_to_bytes(write_datazp, sv[i]);

			if ((send(socket_fd, write_datazp, key_sizezp,
				  0)) == -1) {
				fprintf(stderr,
					"Failure Sending Message\n");
				close(socket_fd);
				break;
			}

			element_to_bytes_compressed(write_data1, Dn[i]);

			if ((send(socket_fd, write_data1, key_size1,
				  0)) == -1) {
				fprintf(stderr,
					"Failure Sending Message\n");
				close(socket_fd);
				break;
			}

			element_to_bytes_compressed(write_data1, En[i]);

			if ((send(socket_fd, write_data1, key_size1,
				  0)) == -1) {
				fprintf(stderr,
					"Failure Sending Message\n");
				close(socket_fd);
				break;
			}
		}

		for (i = 0; i < k; i++) {
			element_init_G1(A[i], pairing);
			element_init_Zr(x[i], pairing);

			memset(buffer, 0, sizeof(buffer));
			num = recv(socket_fd, buffer, key_size1, 0);
			if (num <= 0) {
				printf("Either Connection Closed or "
				       "Error\n");
				break;
			}
			element_from_bytes_compressed(A[i], (unsigned char *) buffer);

			memset(buffer, 0, sizeof(buffer));
			num = recv(socket_fd, buffer, key_sizezp, 0);
			if (num <= 0) {
				printf("Either Connection Closed or "
				       "Error\n");
				break;
			}
			element_from_bytes(x[i], (unsigned char *) buffer);
		}

		memset(buffer, 0, sizeof(buffer));
		num = recv(socket_fd, buffer, key_sizezp, 0);
		if (num <= 0) {
			printf("Either Connection Closed or Error\n");
			break;
		}
		element_from_bytes(mu2, (unsigned char *) buffer);

		t0 = pbc_get_time();

		for (i = 0; i < k; i++) {
			element_pow2_zn(tmp2, w[0], one, g2, x[i]);
			element_pairing(tmpt, A[i], tmp2);

			element_pow3_zn(tmp1, g1, one, K1, one, h2,
					mu2);
			element_pairing(tmpt2, tmp1, g2);

			if (element_cmp(tmpt, tmpt2))
				printf("\n signCre[%d] verif not "
				       "passed bro!\n",
				       i);
			// output signCre[i] = (mu, A[i], x[i])
		}
		t1 = pbc_get_time();
		host = host + (t1 - t0);
		//printf("\tTPM, time elapsed %.2fms\n", tpm * 1000);
		//printf("\tHost, time elapsed %.2fms\n", host * 1000);
		//printf("Remove this time: %.2fms\n", (t1 - t0) * 1000);
		//printf("%.02f\n", (t1-t0) * 1000);
		epid_sign += host + tpm - (t1 - t0);
		gsk_tpm += tpm;
		gsk_host += host; 
		tpm = 0;
		host = 0;

		// Sign --------------------------------------
		//printf("Sign :\n");

		t0 = pbc_get_time();

		// HOST
		// select tuple choosing k
		r = rand();
		r %= k;

		generate_x_check_ecc(D, x[r]);
		t1 = pbc_get_time();
		host = host + (t1 - t0);
		//*******************************************START

		unsigned char xjk[32];
		unsigned char d2[32];
		element_to_bytes(xjk, x[r]);
		element_to_bytes(d2, element_y(D));

		// TPM

		// forward (E, S10, S20) to Host
		unsigned char E_x[32];
		unsigned char E_y[32];
		unsigned char S1s_x[32];
		unsigned char S1s_y[32];
		unsigned char S2s_x[32];
		unsigned char S2s_y[32];
		commit_cntr = malloc(sizeof(uint16_t));
	
		rc = signP1(h1_x, h1_y, xjk, d2, E_x, E_y,
			S1s_x, S1s_y, S2s_x, S2s_y, commit_cntr, time_taken);
		if (rc != 0) {
			perror("signP1 failed");
			exit(1);
		}
		unsigned char E_buf[64];
		memcpy(E_buf, E_x, 32);
		memcpy(E_buf + 32, E_y, 32);
		element_from_bytes(E, E_buf);

		unsigned char S1s_buf[64];
		memcpy(S1s_buf, S1s_x, 32);
		memcpy(S1s_buf + 32, S1s_y, 32);
		element_from_bytes(S10, S1s_buf);

		unsigned char S2s_buf[64];
		memcpy(S2s_buf, S2s_x, 32);
		memcpy(S2s_buf + 32, S2s_y, 32);
		element_from_bytes(S20, S2s_buf);
		tpm = tpm + *time_taken;

		//*******************************************END

		// HOST here
		t0 = pbc_get_time();

		element_random(delta);
		element_pow2_zn(T1, A[r], one, h3, delta);
		element_random(rd);
		element_random(rz);

		element_mul(R1, S10, one);
		element_mul(tmpr, x[r], rd);
		element_pow3_zn(tmp1, S20, one, h2, rz, h3, tmpr);
		element_pairing(tmpt, tmp1, g2);
		element_pairing(tmpt2, h3, w[0]);
		element_pow_zn(tmpt2, tmpt2, rd);
		element_mul(R4, tmpt, tmpt2);

		memset(ibuf, 0, sizeof(ibuf));
		memset(jbuf, 0, sizeof(jbuf));
		current_offset = element_to_bytes(ibuf, D);
		bytes_written = element_to_bytes(jbuf, E);
		memcpy(ibuf + current_offset, jbuf, bytes_written);

		current_offset += bytes_written;
		bytes_written = element_to_bytes(jbuf, T1);
		memcpy(ibuf + current_offset, jbuf, bytes_written);
		
		current_offset += bytes_written;
		bytes_written = element_to_bytes(jbuf, R1);
		memcpy(ibuf + current_offset, jbuf, bytes_written);
		
		current_offset += bytes_written;
		bytes_written = element_to_bytes(jbuf, R4);
		memcpy(ibuf + current_offset, jbuf, bytes_written);

		current_offset += bytes_written;
		SHA256(ibuf, current_offset, obuf);
		element_from_hash(c, obuf, 32);
		// send 'c' to TPM

		t1 = pbc_get_time();
		host = host + (t1 - t0);
		//*******************************************START
		char *M = "Lucifer";
		uint32_t M_len = 7;
		// TPM again
		//t0 = pbc_get_time();
		
		err = fread(&nm, 4, 1, fp); // read 4 bytes /dev/urandom
		if (err != 1) {
			perror("read urandom failed");
			exit(1);
		}

		unsigned char chs[32];
		element_to_bytes(chs, c);

		unsigned char sfs[32];
		unsigned char cts[32];
		rc = signP2(*commit_cntr, nm, chs, M, M_len, sfs, cts, time_taken);
		if (rc != 0) {
			perror("signP2 failed");
			exit(1);
		}
		free(commit_cntr);
		element_from_bytes(sf, sfs);
		element_from_bytes(ct, cts);

		//t1 = pbc_get_time();
		//tpm = tpm + (t1 - t0);
		tpm += *time_taken;
		//*******************************************END

		// HOST
		t0 = pbc_get_time();

		element_mul(sd, ct, delta);
		element_add(sd, rd, sd);
		element_mul(sz, ct, mu);
		element_add(sz, rz, sz);

		// signature sigma-s = (x[r], D->y, E, T1, ct, sf, sz,
		// sd)
		// send (nm, M, sig-s) to Verifier

		t1 = pbc_get_time();
		host = host + (t1 - t0);
		sign_host += host;
		sign_tpm += tpm;
		//printf("\tTPM, time elapsed %.2fms\n", tpm * 1000);
		//printf("\tHost, time elapsed %.2fms\n", host * 1000);

		tpm = 0;
		host = 0;

		// Verify
		t0 = pbc_get_time();

		element_neg(tmpr, ct);
		element_pow2_zn(R1t, D, sf, E, tmpr);

		element_pairing(tmpt, h1, g2);
		element_pow_zn(tmpt, tmpt, sf);
		element_pairing(tmpt2, h2, g2);
		element_pow_zn(tmpt2, tmpt2, sz);
		element_mul(R4t, tmpt, tmpt2);
		element_pairing(tmpt, g1, g2);
		element_pow_zn(tmpt, tmpt, ct);
		element_mul(R4t, tmpt, R4t);
		element_pow2_zn(tmp1, T1, tmpr, h3, sd);
		element_pow2_zn(tmp2, w[0], one, g2, x[r]);
		element_pairing(tmpt2, tmp1, tmp2);
		element_mul(R4t, R4t, tmpt2);

		memset(ibuf, 0, sizeof(ibuf));
		memset(jbuf, 0, sizeof(jbuf));
		current_offset = element_to_bytes(ibuf, D);
		bytes_written = element_to_bytes(jbuf, E);
		memcpy(ibuf + current_offset, jbuf, bytes_written);
		
		current_offset += bytes_written;
		bytes_written = element_to_bytes(jbuf, T1);
		memcpy(ibuf + current_offset, jbuf, bytes_written);

		current_offset += bytes_written;
		bytes_written = element_to_bytes(jbuf, R1t);
		memcpy(ibuf + current_offset, jbuf, bytes_written);

		current_offset += bytes_written;
		bytes_written = element_to_bytes(jbuf, R4t);
		memcpy(ibuf + current_offset, jbuf, bytes_written);

		current_offset += bytes_written;
		SHA256(ibuf, current_offset, obuf);
		element_from_hash(c, obuf, 32);

		memset(ibuf, 0, sizeof(ibuf));
		memset(jbuf, 0, sizeof(jbuf));
		current_offset = element_to_bytes(ibuf, c);
		memcpy(ibuf + current_offset, &nm, 4);
		current_offset += 4;
		memcpy(ibuf + current_offset, M, strlen(M));
		current_offset += strlen(M);
		SHA256(ibuf, current_offset, obuf);
		element_from_hash(cq, obuf, 32);

		if (element_cmp(ct, cq))
			printf("Verifier verification not passed for "
			       "c! -_-\n");

		t1 = pbc_get_time();
		//printf(
		//    "Verifier, time elapsed %.2fms\n\n--------\n",
		//    (t1 - t0) * 1000);
		verify += t1 - t0;
		// check for x[k] in atRL - Rev.c
		// valid or invalid

		// Revoke -------------------------------------
	}
	close(socket_fd);
	fclose(fp);

	gmk_tpm /= iterations;
	gmk_host /= iterations;
	gsk_tpm /= iterations;
	gsk_host /= iterations;
	sign_host /= iterations;
	sign_tpm /= iterations;
	verify /= iterations;
	epid_sign /= iterations;
	printf("GetMemKey TPM: %.2fms\n", gmk_tpm * 1000);
	printf("GetMemKey Host: %.2fms\n", gmk_host * 1000);
	printf("GetSignKey TPM: %.2fms\n", gsk_tpm * 1000);
	printf("GetSignKey Host: %.2fms\n", gsk_host * 1000);
	printf("Sign TPM: %.2fms\n", sign_tpm * 1000);
	printf("Sign Host: %.2fms\n", sign_host * 1000);
	printf("Verify: %.2fms\n", verify * 1000);
	printf("EPID Sign: %.2fms\n", epid_sign * 1000);
	
	
	
	
	
	
	

	for (i = 0; i < nr; i++) {
		element_clear(Dn[i]);
		element_clear(F[i]);
		element_clear(S1[i]);
		element_clear(S2[i]);
		element_clear(En[i]);
		element_clear(P[i]);
		element_clear(RI[i]);
		element_clear(RII[i]);
		element_clear(tow[i]);
		element_clear(rt[i]);
		element_clear(sp[i]);
		element_clear(cpt[i]);
		element_clear(st[i]);
		element_clear(sv[i]);
	}

	for (i = 0; i < k; i++) {
		element_clear(w[i]);
		element_clear(x[i]);
		element_clear(A[i]);
	}

	element_clear(g1);
	element_clear(g2);
	element_clear(h1);
	element_clear(h2);
	element_clear(h3);
	element_clear(gamma);
	element_clear(cnt);
	element_clear(PI);
	element_clear(DAAseed);
	element_clear(bsn);
	element_clear(bsnn);
	element_clear(I);
	element_clear(J);
	element_clear(D);
	element_clear(E);
	element_clear(K1);
	element_clear(K2);
	element_clear(T1);
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
	element_clear(eeta);
	element_clear(mu);
	element_clear(mu1);
	element_clear(mu2);
	element_clear(rho);
	element_clear(xi);
	element_clear(rd);
	element_clear(rf);
	element_clear(rz);
	element_clear(rxi);
	element_clear(reta);
	element_clear(rrho);
	element_clear(rmu);
	element_clear(sd);
	element_clear(sf);
	element_clear(sz);
	element_clear(sxi);
	element_clear(seta);
	element_clear(srho);
	element_clear(smu);
	element_clear(c);
	element_clear(ct);
	element_clear(cq);
	element_clear(one);
	element_clear(index);
	pairing_clear(pairing);

	free(time_taken);
	return 0;
}

/*
 * Sets elem to be a point on the curve such that
 * preimg's data is the preimage of the x parameter of the curve
 */
void generate_x_check_ecc(element_t elem, element_t preimg) {
	
	curve_data_ptr cdp = elem->field->data;
	point_ptr pt = elem->data;
	element_t tmp;
	element_init(tmp, cdp->field);
	pt->inf_flag = 0;

	unsigned char buf[32];
	unsigned char obuf[32];
	do {
		element_random(preimg);
		memset(buf, 0, 32);
		element_to_bytes(buf, preimg);
		SHA256(buf, 32, obuf);
		element_from_hash(pt->x, obuf, 32);

		element_square(tmp, pt->x);
		element_add(tmp, tmp, cdp->a);
		element_mul(tmp, tmp, pt->x);
		element_add(tmp, tmp, cdp->b);
	} while (!element_is_sqr(tmp));
	element_sqrt(pt->y, tmp);
	element_clear(tmp);
} 
