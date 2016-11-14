#include "laser_utils.h"

int main(int argc, char **argv)
{
	if (argc < 4) {
		printf("Usage: ./laser_issuer param_file num_alias_tokens revoked_user_cnt\n");
		exit(1);
	}
	int iterations;
	if (argc == 4) {
		iterations = 1;
	}
	else
	{
		iterations = (int) strtol(argv[4], NULL, 10);
	}
	
	srand(time(NULL));

	pairing_t pairing;
	element_t g1, g2, h1, h2;
	element_t gamma;
	element_t cnt, PI, DAAseed, bsn, bsnn;
	element_t f, p, h3, z;
	element_t A0, D, E, I, J, K1, K2, S10, S20;
	element_t delta, eeta, mu, mu1, mu2, rho, xi;
	element_t rd, rf, rrho, rz, rxi, reta, rmu;
	element_t sd, sf, srho, sz, sxi, seta, smu;
	element_t c, ct, cq;
	element_t tmp1, tmp11, tmp2, tmp22, tmpt, tmpt2, tmpr, tmpc;
	element_t index, one;
	element_t T1, R1, R2, R3, R1t, R2t, R3t, R4, R4t;
	element_pp_t gp1, gp2;

	int i;
	int k = (int) strtol(argv[2], NULL, 10); 
	printf("Number of Alias Tokens: %d\n", k);
	int nr = (int) strtol(argv[3], NULL, 10);
	printf("Number of Revoked Basenames: %d\n", nr);
	printf("Iterations: %d\n", iterations);
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
	element_t cqt[nr];
	element_t st[nr];
	element_t sp[nr];
	element_t sv[nr];
	element_t rt[nr];
	element_t rp[nr];
	uint32_t nn[nr];

	element_t A[k];
	element_pp_t wp[k];

	int key_size1, key_size2, key_sizezp;

	double t0 = 0, t1 = 0;
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

	element_init_G1(A0, pairing);
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

	printf("\t----- LASER scheme ----- \n\n");

	struct sockaddr_in server;
	struct sockaddr_in dest;
	int socket_fd, client_fd, num;
	socklen_t size;

	char buffer[MAXSIZE];
	memset(buffer, 0, sizeof(buffer));
	uint32_t yes = 1;

	uint32_t bytes_written = 0;
	uint32_t current_offset = 0; 

	if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		fprintf(stderr, "Socket failure!!\n");
		exit(1);
	}

	if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &yes,
		       sizeof(int)) == -1) {
		perror("setsockopt");
		exit(1);
	}
	memset(&server, 0, sizeof(server));
	memset(&dest, 0, sizeof(dest));
	server.sin_family = AF_INET;
	server.sin_port = htons(PORT);
	server.sin_addr.s_addr = INADDR_ANY;
	if ((bind(socket_fd, (struct sockaddr *)&server,
		  sizeof(struct sockaddr))) == -1) { // sizeof(struct sockaddr)
		fprintf(stderr, "Binding Failure\n");
		exit(1);
	}

	if ((listen(socket_fd, BACKLOG)) == -1) {
		fprintf(stderr, "Listening Failure\n");
		exit(1);
	}

	// KeyGen ---------------------------------------

	t0 = pbc_get_time();

	element_random(g1);
	element_random(g2);

	unsigned char ptx[32] = {0x00};
	unsigned char pty[32] = {0x00};
	unsigned char QW[64];

	ptx[31] = 0x01;
	pty[31] = 0x02;

	memcpy(QW, ptx, 32);
	memcpy(QW + 32, pty, 32);

	element_from_bytes_compressed(h1, QW);

	element_random(h2);
	element_random(gamma);
	element_random(h3);
	element_pp_init(gp1, g1);
	element_pp_init(gp2, g2);

	element_set1(index);
	for (i = 0; i < k; i++) // k is 'ma'
	{
		element_init_G2(w[i], pairing);
		element_pow_zn(tmpr, gamma, index);
		element_pp_pow_zn(w[i], tmpr, gp2);

		element_pp_init(wp[i], w[i]);

		element_add(index, index, one);
	}

	// group public key 'gpk'
	// issuer's secret key 'isk'

	t1 = pbc_get_time();
	printf("KeyGen : \n \tIssuer time elapsed %.2fms\n\n",
	       (t1 - t0) * 1000);

	unsigned char *write_data1, *write_data2, *write_datazp;
	key_size1 = element_length_in_bytes_compressed(g1);
	write_data1 = pbc_malloc(key_size1);
	key_size2 = element_length_in_bytes_compressed(g2);
	write_data2 = pbc_malloc(key_size2);
	
	uint32_t nm = 0;
	uint32_t nmm = 0;
	FILE *fp;
	fp = fopen("/dev/urandom", "r");
	int err;
	element_random(DAAseed);
	key_sizezp = element_length_in_bytes(DAAseed);
	write_datazp = pbc_malloc(key_sizezp);

	while (1) {
		size = sizeof(struct sockaddr_in);

		if ((client_fd = accept(socket_fd, (struct sockaddr *)&dest,
					&size)) == -1) {
			perror("accept");
			exit(1);
		}
		printf("Server got connection from client %s\n",
		       inet_ntoa(dest.sin_addr));

		while (1) {
			element_to_bytes_compressed(write_data1, h1);

			if ((send(client_fd, write_data1, key_size1, 0)) ==
			    -1) {
				fprintf(stderr, "Failure Sending Message\n");
				close(client_fd);
				break;
			}

			element_to_bytes_compressed(write_data1, h2);

			if ((send(client_fd, write_data1, key_size1, 0)) ==
			    -1) {
				fprintf(stderr, "Failure Sending Message\n");
				close(client_fd);
				break;
			}

			element_to_bytes_compressed(write_data1, g1);

			if ((send(client_fd, write_data1, key_size1, 0)) ==
			    -1) {
				fprintf(stderr, "Failure Sending Message\n");
				close(client_fd);
				break;
			}

			element_to_bytes_compressed(write_data2, g2);

			if ((send(client_fd, write_data2, key_size2, 0)) ==
			    -1) {
				fprintf(stderr, "Failure Sending Message\n");
				close(client_fd);
				break;
			}

			element_to_bytes_compressed(write_data1, h3);

			if ((send(client_fd, write_data1, key_size1, 0)) ==
			    -1) {
				fprintf(stderr, "Failure Sending Message\n");
				close(client_fd);
				break;
			}

			for (i = 0; i < k; i++) // k is 'ma'
			{

				element_to_bytes_compressed(write_data2, w[i]);

				if ((send(client_fd, write_data2, key_size2,
					  0)) == -1) {
					fprintf(stderr,
						"Failure Sending Message\n");
					close(client_fd);
					break;
				}
			}

			//printf("KeyGen elements sent! \n\n");

			// GetMemKey - Issuer generates nonce

			printf("GetMemKey : \n");

			memset(buffer, 0, sizeof(buffer));
			if ((num = recv(client_fd, buffer, 102, 0)) == -1) {
				perror("recv");
				exit(1);
			}

			//element_to_bytes(write_datazp, nm); // 32-bit nonce

			err = fread(&nm, 4, 1, fp);
			if (err != 1) {
				perror("read urandom failed");
				exit(1);
			}

			if ((send(client_fd, &nm, 4, 0)) ==
			    -1) {
				fprintf(stderr, "Failure Sending Message\n");
				close(client_fd);
				break;
			}

			// GetMemKey - step 6

			memset(buffer, 0, sizeof(buffer));
			num = recv(client_fd, buffer, key_size1, 0);
			if (num <= 0) {
				printf("Either Connection Closed or Error\n");
				break;
			}
			element_from_bytes_compressed(I, (unsigned char*) buffer);

			memset(buffer, 0, sizeof(buffer));
			num = recv(client_fd, &nm, 4, 0);
			if (num <= 0) {
				printf("Either Connection Closed or Error\n");
				break;
			}
			//element_from_bytes(nm, (unsigned char*) buffer);

			memset(buffer, 0, sizeof(buffer));
			num = recv(client_fd, &nmm, 4, 0);
			if (num <= 0) {
				printf("Either Connection Closed or Error\n");
				break;
			}
			//element_from_bytes(nmm, (unsigned char*) buffer);

			memset(buffer, 0, sizeof(buffer));
			num = recv(client_fd, buffer, key_sizezp, 0);
			if (num <= 0) {
				printf("Either Connection Closed or Error\n");
				break;
			}
			element_from_bytes(c, (unsigned char*) buffer);

			memset(buffer, 0, sizeof(buffer));
			num = recv(client_fd, buffer, key_sizezp, 0);
			if (num <= 0) {
				printf("Either Connection Closed or Error\n");
				break;
			}
			element_from_bytes(sf, (unsigned char*) buffer);

			t0 = pbc_get_time();

			element_neg(tmpr, c);
			element_pow2_zn(R1t, h1, sf, I, tmpr);

			memset(ibuf, 0, sizeof ibuf);
			memset(jbuf, 0, sizeof jbuf);
			memcpy(ibuf, &nm, 4);
			current_offset = 4;
			bytes_written = element_to_bytes(jbuf, I);
			memcpy(ibuf + current_offset, jbuf, bytes_written);

			current_offset += bytes_written;
			bytes_written = element_to_bytes(jbuf, R1t);
			memcpy(ibuf + current_offset, jbuf, bytes_written);

			current_offset += bytes_written;
			SHA256(ibuf, current_offset, obuf);
			element_from_hash(ct, obuf, 32);

			memset(ibuf, 0, sizeof ibuf);
			memset(jbuf, 0, sizeof jbuf);
			current_offset = element_to_bytes(ibuf, ct);
			memcpy(ibuf + current_offset, &nmm, 4);
			current_offset += 4;
			SHA256(ibuf, current_offset, obuf);
			element_from_hash(cq, obuf, 32);

			if (element_cmp(c, cq))
				printf("GetMemKey 5(b) verification not "
				       "passed! :( \n");

			element_random(z);
			element_random(rho);
			element_add(tmpr, gamma, z);
			element_invert(tmpr, tmpr);
			element_pow_zn(tmp1, h2, rho);
			element_mul(tmp11, g1, I);
			element_mul(J, tmp1, tmp11);
			element_pow_zn(J, J, tmpr);
			// send (J, z, rho) to host

			t1 = pbc_get_time();
			printf("\tIssuer, time elapsed %.2fms\n\n",
			       (t1 - t0) * 1000);

			element_to_bytes_compressed(write_data1, J); // namma
								     // add

			if ((send(client_fd, write_data1, key_size1, 0)) ==
			    -1) {
				fprintf(stderr, "Failure Sending Message\n");
				close(client_fd);
				break;
			}

			element_to_bytes(write_datazp, z); // namma add

			if ((send(client_fd, write_datazp, key_sizezp, 0)) ==
			    -1) {
				fprintf(stderr, "Failure Sending Message\n");
				close(client_fd);
				break;
			}

			element_to_bytes(write_datazp, rho); // namma add

			if ((send(client_fd, write_datazp, key_sizezp, 0)) ==
			    -1) {
				fprintf(stderr, "Failure Sending Message\n");
				close(client_fd);
				break;
			}

			printf("GetSignKey : \n");

			// GetSignKey

			memset(buffer, 0, sizeof(buffer));
			num = recv(client_fd, &nm, 4, 0);
			if (num <= 0) {
				printf("Either Connection Closed or Error\n");
				break;
			}
			//element_from_bytes(nm, (unsigned char*)buffer);

			memset(buffer, 0, sizeof(buffer)); // recv bsn and D->y
			num = recv(client_fd, buffer, key_size1, 0);
			if (num <= 0) {
				printf("Either Connection Closed or Error\n");
				break;
			}
			element_from_bytes_compressed(D, (unsigned char*)buffer);

			memset(buffer, 0, sizeof(buffer));
			num = recv(client_fd, buffer, key_size1, 0);
			if (num <= 0) {
				printf("Either Connection Closed or Error\n");
				break;
			}
			element_from_bytes_compressed(E, (unsigned char*) buffer);

			memset(buffer, 0, sizeof(buffer));
			num = recv(client_fd, buffer, key_size1, 0);
			if (num <= 0) {
				printf("Either Connection Closed or Error\n");
				break;
			}
			element_from_bytes_compressed(K1, (unsigned char*)buffer);

			memset(buffer, 0, sizeof(buffer));
			num = recv(client_fd, buffer, key_size1, 0);
			if (num <= 0) {
				printf("Either Connection Closed or Error\n");
				break;
			}
			element_from_bytes_compressed(K2, (unsigned char*) buffer);

			memset(buffer, 0, sizeof(buffer));
			num = recv(client_fd, buffer, key_sizezp, 0);
			if (num <= 0) {
				printf("Either Connection Closed or Error\n");
				break;
			}
			element_from_bytes(ct, (unsigned char*) buffer);

			memset(buffer, 0, sizeof(buffer));
			num = recv(client_fd, buffer, key_sizezp, 0);
			if (num <= 0) {
				printf("Either Connection Closed or Error\n");
				break;
			}
			element_from_bytes(sf, (unsigned char*)buffer);

			memset(buffer, 0, sizeof(buffer));
			num = recv(client_fd, buffer, key_sizezp, 0);
			if (num <= 0) {
				printf("Either Connection Closed or Error\n");
				break;
			}
			element_from_bytes(smu, (unsigned char*)buffer);

			memset(buffer, 0, sizeof(buffer));
			num = recv(client_fd, buffer, key_sizezp, 0);
			if (num <= 0) {
				printf("Either Connection Closed or Error\n");
				break;
			}
			element_from_bytes(sz, (unsigned char*) buffer);

			memset(buffer, 0, sizeof(buffer));
			num = recv(client_fd, buffer, key_sizezp, 0);
			if (num <= 0) {
				printf("Either Connection Closed or Error\n");
				break;
			}
			element_from_bytes(sxi, (unsigned char*) buffer);

			memset(buffer, 0, sizeof(buffer));
			num = recv(client_fd, buffer, key_sizezp, 0);
			if (num <= 0) {
				printf("Either Connection Closed or Error\n");
				break;
			}
			element_from_bytes(seta, (unsigned char*)buffer);

			memset(buffer, 0, sizeof(buffer));
			num = recv(client_fd, buffer, key_sizezp, 0);
			if (num <= 0) {
				printf("Either Connection Closed or Error\n");
				break;
			}
			element_from_bytes(srho, (unsigned char*)buffer);

			t0 = pbc_get_time();
			// compute D from (bsn, D->y)

			element_neg(tmpc, ct);
			element_pow2_zn(R1t, D, sf, E, tmpc);

			element_pow3_zn(R2t, h1, sf, h2, smu, K1, tmpc);

			element_pow3_zn(tmp1, h1, sf, h2, srho, g1, ct);
			element_neg(tmpr, sz);
			element_pow3_zn(tmp1, K2, tmpr, h3, seta, tmp1, one);
			element_pairing(tmpt, tmp1, g2);
			element_pow2_zn(tmp11, h3, sxi, K2, tmpc);
			element_pairing(tmpt2, tmp11, w[0]); // wd!
			element_mul(R3t, tmpt, tmpt2);

			memset(ibuf, 0, sizeof ibuf);
			memset(jbuf, 0, sizeof jbuf);
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
			bytes_written = element_to_bytes(jbuf, R1t);
			memcpy(ibuf + current_offset, jbuf, bytes_written);
			
			current_offset += bytes_written;
			bytes_written = element_to_bytes(jbuf, R2t);
			memcpy(ibuf + current_offset, jbuf, bytes_written);
			
			current_offset += bytes_written;
			bytes_written = element_to_bytes(jbuf, R3t);
			memcpy(ibuf + current_offset, jbuf, bytes_written);
			
			current_offset += bytes_written;
			SHA256(ibuf, current_offset, obuf);
			element_from_hash(c, obuf, 32);

			memset(ibuf, 0, sizeof ibuf);
			memset(jbuf, 0, sizeof jbuf);
			current_offset = element_to_bytes(ibuf, c);
			memcpy(ibuf + current_offset, &nm, 4);
			current_offset += 4;
			SHA256(ibuf, current_offset, obuf);
			element_from_hash(cq, obuf, 32);

			if (element_cmp(cq, ct))
				printf("\n GetSignKey Issuer 4(c) verification "
				       "not passed! :O \n");

			for (i = 0; i < nr; i++) {
				//element_init_Zr(nn[i], pairing);
				element_init_G1(P[i], pairing);
				element_init_Zr(cpt[i], pairing);
				element_init_Zr(st[i], pairing);
				element_init_Zr(sv[i], pairing);

				memset(buffer, 0, sizeof(buffer));
				num = recv(client_fd, &nn[i], 4, 0);
				if (num <= 0) {
					printf("Either Connection Closed or "
					       "Error\n");
					break;
				}
				//element_from_bytes(nn[i], (unsigned char*) buffer);

				memset(buffer, 0, sizeof(buffer));
				num = recv(client_fd, buffer, key_size1, 0);
				if (num <= 0) {
					printf("Either Connection Closed or "
					       "Error\n");
					break;
				}
				element_from_bytes_compressed(P[i], (unsigned char*) buffer);

				memset(buffer, 0, sizeof(buffer));
				num = recv(client_fd, buffer, key_sizezp, 0);
				if (num <= 0) {
					printf("Either Connection Closed or "
					       "Error\n");
					break;
				}
				element_from_bytes(cpt[i], (unsigned char*) buffer);

				memset(buffer, 0, sizeof(buffer));
				num = recv(client_fd, buffer, key_sizezp, 0);
				if (num <= 0) {
					printf("Either Connection Closed or "
					       "Error\n");
					break;
				}
				element_from_bytes(st[i], (unsigned char*) buffer);

				memset(buffer, 0, sizeof(buffer));
				num = recv(client_fd, buffer, key_sizezp, 0);
				if (num <= 0) {
					printf("Either Connection Closed or "
					       "Error\n");
					break;
				}
				element_from_bytes(sv[i], (unsigned char*)buffer);

				memset(buffer, 0, sizeof(buffer));
				num = recv(client_fd, buffer, key_size1, 0);
				if (num <= 0) {
					printf("Either Connection Closed or "
					       "Error\n");
					break;
				}
				element_init_G1(Dn[i], pairing);
				element_from_bytes_compressed(Dn[i], (unsigned char*) buffer);

				memset(buffer, 0, sizeof(buffer));
				num = recv(client_fd, buffer, key_size1, 0);
				if (num <= 0) {
					printf("Either Connection Closed or "
					       "Error\n");
					break;
				}
				element_init_G1(En[i], pairing);
				element_from_bytes_compressed(En[i], (unsigned char*) buffer);

				element_init_G1(RI[i], pairing);
				element_init_G1(RII[i], pairing);

				element_neg(tmpr, st[i]);
				element_neg(tmpc, cpt[i]);
				element_pow3_zn(RI[i], Dn[i], sv[i], En[i],
						tmpr, P[i], tmpc);
				element_pow2_zn(RII[i], E, tmpr, D, sv[i]);

				memset(ibuf, 0, sizeof ibuf);
				memset(jbuf, 0, sizeof jbuf);
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
				//element_init_Zr(cp[i], pairing);
				//element_from_hash(cp[i], obuf, 32);

				memset(ibuf, 0, sizeof ibuf);
				memset(jbuf, 0, sizeof jbuf);
				//current_offset = element_to_bytes(ibuf, cp[i]);
				memcpy(ibuf, cp[i], 32);
				current_offset = 32;
				memcpy(ibuf + current_offset, &nn[i], 4);
				
				current_offset += 4;
				SHA256(ibuf, current_offset, obuf);
				element_init_Zr(cqt[i], pairing);
				element_from_hash(cqt[i], obuf, 32);

				if (element_cmp(cqt[i], cpt[i]))
					printf("GetSignKey Issuer 5(c) "
					       "verification not passed! >.< "
					       "\n");

				if (!element_cmp(P[i], one))
					printf("GetSignKey Issuer 5(d) "
					       "verification not passed! :/ "
					       "\n");
			}

			element_random(mu2);
			element_mul(tmp1, g1, K1);
			element_pow2_zn(A0, tmp1, one, h2, mu2);

			for (i = 0; i < k; i++) {
				element_t dummy;
				element_init_G1(dummy, pairing);
				element_init_Zr(x[i], pairing);

				generate_x_check_ecc(dummy, x[i]);
				// TODO: Make sure x[i] hashes to a
				// x param with assoc. y param on ECC. 
				// writing function call to replace do loops
				// in the platform code, can use this here as
				// well to make this check happen.

				element_add(tmpr, gamma, x[i]);
				element_div(p, one, tmpr);

				element_init_G1(A[i], pairing);
				element_pow_zn(A[i], A0, p);
			}

			// append tuple (bsn, D->y, E, x1, ..., xk) to database
			// reg
			// send (mu2, A[0], ..., A[k-1], x[0], ..., x[k-1]) to
			// Host

			t1 = pbc_get_time();
			printf("\tIssuer, time elapsed %.2fms\n\n",
			       (t1 - t0) * 1000);

			for (i = 0; i < k; i++) {

				element_to_bytes_compressed(write_data1, A[i]);

				if ((send(client_fd, write_data1, key_size1,
					  0)) == -1) {
					fprintf(stderr,
						"Failure Sending Message\n");
					close(client_fd);
					break;
				}

				element_to_bytes(write_datazp, x[i]);

				if ((send(client_fd, write_datazp, key_sizezp,
					  0)) == -1) {
					fprintf(stderr,
						"Failure Sending Message\n");
					close(client_fd);
					break;
				}
			}

			element_to_bytes(write_datazp, mu2);

			if ((send(client_fd, write_datazp, key_sizezp, 0)) ==
			    -1) {
				fprintf(stderr, "Failure Sending Message\n");
				close(client_fd);
				break;
			}

			printf("GetSignCredentials sent! \n");

		} // End of Inner While...
		// Close Connection Socket
		close(client_fd);
	} // Outer While
	close(socket_fd);
	fclose(fp);

	for (i = 0; i < nr; i++) {
		element_clear(Dn[i]);
		element_clear(F[i]);
		element_clear(S1[i]);
		element_clear(S2[i]);
		element_clear(En[i]);
		element_clear(P[i]);
		element_clear(RI[i]);
		element_clear(RII[i]);
		//element_clear(nn[i]);
		element_clear(rp[i]);
		element_clear(tow[i]);
		element_clear(rt[i]);
		//element_clear(cp[i]);
		element_clear(sp[i]);
		element_clear(cpt[i]);
		element_clear(cqt[i]);
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
	element_clear(A0);
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
