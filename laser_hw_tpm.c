#include "laser_tpm.h"

static double t0 = 0;
static double t1 = 0;
static TPMI_DH_OBJECT pkey_handle;
static TSS_CONTEXT *tssContext;
static TPMI_DH_OBJECT auth_handle;


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
		    )
{
	TPM_RC				rc = 0;
	/* Table 50 - TPMI_RH_HIERARCHY primaryHandle */
	Commit_In			commitIn;
	Commit_Out			commitOut;

	/* input the point h1 and configure options for TPM2_Commit */
	if (rc == 0) {
		//commitIn.signHandle = createPrimaryOut.objectHandle;
		commitIn.signHandle = pkey_handle;
		if (P1_x != NULL && P1_y != NULL) {	
			commitIn.P1.size = 32 + 32 + 2 + 2;
			commitIn.P1.point.x.t.size = 32;
			commitIn.P1.point.y.t.size = 32;
			memcpy(commitIn.P1.point.x.t.buffer, P1_x, 32);
			memcpy(commitIn.P1.point.y.t.buffer, P1_y, 32);
		}
		else {
			commitIn.P1.size = 0;
		}
		if (s2 != NULL && y2 != NULL) {
			commitIn.s2.t.size = 32;
			memcpy(commitIn.s2.t.buffer, s2, 32);
			commitIn.y2.t.size = 32;
			memcpy(commitIn.y2.t.buffer, y2, 32);
		}
		else {
			commitIn.s2.t.size = 0;
			commitIn.y2.t.size = 0;
		}
	}
	/* call TPM2_Commit */
	if (rc == 0) {
		t0 = pbc_get_time();
		rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&commitOut,
			 (COMMAND_PARAMETERS *)&commitIn,
			 NULL,
			 TPM_CC_Commit,
			 auth_handle, NULL, 1,
			 TPM_RH_NULL, NULL, 0);
		t1 = pbc_get_time();
		*time_taken = t1 - t0;
	}
	/* Output */
	if (rc == 0) {	
		if (s2 != NULL && y2 != NULL) {
			memcpy(K_x, commitOut.K.point.x.t.buffer, 32);
			memcpy(K_y, commitOut.K.point.y.t.buffer, 32);
			memcpy(L_x, commitOut.L.point.x.t.buffer, 32);
			memcpy(L_y, commitOut.L.point.y.t.buffer, 32);
		}
		if (P1_x != NULL && P1_y != NULL) {
			memcpy(E_x, commitOut.E.point.x.t.buffer, 32);
			memcpy(E_y, commitOut.E.point.y.t.buffer, 32);
		}
		*cntr = commitOut.counter;
	}
	return rc;
}

TPM_RC sign_helper(
			uint16_t cntr,
			uint32_t nonce,
			unsigned char *hash,
			char *msg,
			uint32_t msg_len,
			unsigned char *r,
			unsigned char *s,
			double *time_taken
		  )
{
	TPM_RC				rc = 0;
	/* Table 50 - TPMI_RH_HIERARCHY primaryHandle */
	Sign_In			        signIn;
	Sign_Out			signOut;
	TPMI_ALG_HASH			halg = TPM_ALG_SHA256;
	uint32_t			sizeInBytes;
	uint16_t 			messageLength; 
	unsigned char			*message;
	TPMT_HA				digest;
	
	/* Produce digest that will be signed */ 
	if (rc == 0) {
		digest.hashAlg = halg;
		sizeInBytes = TSS_GetDigestSize(digest.hashAlg);
		messageLength = sizeInBytes + sizeof(uint32_t) + msg_len;
		message = malloc(messageLength);
		memcpy(message, hash, sizeInBytes);
		memcpy(message + sizeInBytes, &nonce, sizeof(uint32_t));
		if (msg != NULL && msg_len != 0) {
			memcpy(message + sizeInBytes + sizeof(uint32_t), msg, msg_len);	
		}
		rc = TSS_Hash_Generate(&digest, messageLength, message, 0, NULL);
		free(message);
	}
	/* Set up inputs for TPM2_Sign */
	if (rc == 0) {
		//signIn.keyHandle = createPrimaryOut.objectHandle;
		signIn.keyHandle = pkey_handle;
		signIn.inScheme.scheme = TPM_ALG_ECDAA;
		signIn.inScheme.details.ecdaa.count = cntr;
		signIn.inScheme.details.ecdaa.hashAlg = halg;
		signIn.digest.t.size = sizeInBytes;
		memcpy(&signIn.digest.t.buffer, (uint8_t *) &digest.digest, sizeInBytes);
		signIn.validation.tag = TPM_ST_HASHCHECK;
		signIn.validation.hierarchy = TPM_RH_NULL;
		signIn.validation.digest.t.size = 0;
	}
	/* Call TPM2_Sign */
	if (rc == 0) {
		t0 = pbc_get_time();
		rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&signOut,
			 (COMMAND_PARAMETERS *)&signIn,
			 NULL,
			 TPM_CC_Sign,
			 auth_handle, NULL, 1,
			 TPM_RH_NULL, NULL, 0);
		t1 = pbc_get_time();
		*time_taken = t1 - t0;
	}

	/* Copy out signature components */
	if (rc == 0) {
		memcpy(r, signOut.signature.signature.ecdaa.signatureR.t.buffer, 32);
		memcpy(s, signOut.signature.signature.ecdaa.signatureS.t.buffer, 32);
	}
	return rc;
}

TPM_RC createMemKeyP1(	
			unsigned char *I_x,
			unsigned char *I_y,
			double *time_taken
			)
{
	TPM_RC				rc = 0;
	/* Table 50 - TPMI_RH_HIERARCHY primaryHandle */
	TPMI_RH_HIERARCHY		primaryHandle = TPM_RH_ENDORSEMENT;
	CreatePrimary_In		createPrimaryIn;
	CreatePrimary_Out		createPrimaryOut;
	StartAuthSession_In		startAuthSessionIn;
	StartAuthSession_Out		startAuthSessionOut;
	TPMI_ALG_HASH			halg = TPM_ALG_SHA256;
	
	/* Start a TSS context, store in a static variable */
	if (rc == 0) {
		rc = TSS_Create(&tssContext);
	}
	if (rc == 0) {
		TSS_SetProperty(tssContext, TPM_INTERFACE_TYPE, "dev");
	}

	/* Start an authorization session */
	if (rc == 0) {
		startAuthSessionIn.sessionType = TPM_SE_HMAC;
		startAuthSessionIn.tpmKey = TPM_RH_NULL;
		startAuthSessionIn.encryptedSalt.b.size = 0;
		startAuthSessionIn.bind = TPM_RH_NULL;
		startAuthSessionIn.nonceCaller.t.size = 0;
		startAuthSessionIn.symmetric.algorithm = TPM_ALG_XOR;
		startAuthSessionIn.symmetric.keyBits.xorr = halg;
		startAuthSessionIn.symmetric.mode.sym = TPM_ALG_NULL;
		startAuthSessionIn.authHash = halg;
	}
	/* call TSS to execute the command */
	if (rc == 0) {
		rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&startAuthSessionOut,
			 (COMMAND_PARAMETERS *)&startAuthSessionIn,
			 NULL,
			 TPM_CC_StartAuthSession,
			 TPM_RH_NULL, NULL, 0);
	}
	/* Copy the authorization session handle to static variable */
	if (rc == 0) {
		auth_handle = startAuthSessionOut.sessionHandle;
	}
	/* Create the primary key from the DAASeed */
	if (rc == 0) {
		createPrimaryIn.primaryHandle = primaryHandle;
		createPrimaryIn.inSensitive.sensitive.data.t.size = 0;
		createPrimaryIn.inSensitive.sensitive.userAuth.t.size = 0;
		createPrimaryIn.inPublic.publicArea.type = TPM_ALG_ECC;
		createPrimaryIn.inPublic.publicArea.nameAlg = halg;
		createPrimaryIn.inPublic.publicArea.objectAttributes.val = 0;
		createPrimaryIn.inPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_FIXEDTPM;
		createPrimaryIn.inPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_FIXEDPARENT;
		createPrimaryIn.inPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
		createPrimaryIn.inPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
		createPrimaryIn.inPublic.publicArea.objectAttributes.val &= ~TPMA_OBJECT_ADMINWITHPOLICY;
		createPrimaryIn.inPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_NODA;
		createPrimaryIn.inPublic.publicArea.objectAttributes.val &= ~TPMA_OBJECT_RESTRICTED;
		createPrimaryIn.inPublic.publicArea.objectAttributes.val &= ~TPMA_OBJECT_DECRYPT;
		createPrimaryIn.inPublic.publicArea.objectAttributes.val |= TPMA_OBJECT_SIGN;
		createPrimaryIn.inPublic.publicArea.authPolicy.t.size = 0;	/* empty policy */
		createPrimaryIn.inPublic.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
		createPrimaryIn.inPublic.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_ECDAA;
		createPrimaryIn.inPublic.publicArea.parameters.eccDetail.curveID = TPM_ECC_BN_P256;
		createPrimaryIn.inPublic.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
		createPrimaryIn.inPublic.publicArea.parameters.eccDetail.kdf.details.mgf1.hashAlg = halg;
		createPrimaryIn.inPublic.publicArea.parameters.eccDetail.scheme.details.ecdaa.hashAlg = halg;
		createPrimaryIn.inPublic.publicArea.unique.ecc.x.t.size = 0;
		createPrimaryIn.inPublic.publicArea.unique.ecc.y.t.size = 0;

		//unsigned char onebuf[32] = {0x00};
		//onebuf[31] = 0x01;
		//unsigned char twobuf[32] = {0x00};
		//twobuf[31] = 0x02;
		/* It appears to make no difference if I set publicArea.unique.ecc or not... */
		/*
		unsigned char onebuf[32] = {0xf9,0x60,0xa1,0x77,0xf4,0xbc,0x4c,0xe6,0xdf,0x76,0x99,0xce,0xb8,0xfa,0x74,0x47,0x3a,0xa5,0xad,0xad,0x4b,0x49,0xd9,0xdf,0xb7,0x14,0x35,0x7c,0x21,0x9e,0xb6,0x0c};
		unsigned char twobuf[32] = {0xe0,0x54,0xcf,0x38,0x1e,0x5e,0xeb,0x78,0x5b,0x3e,0xf6,0x83,0x05,0x49,0xe4,0x74,0x93,0x5e,0x19,0xa7,0xda,0x46,0x00,0x8a,0xd1,0xa4,0x4c,0xc0,0xf6,0x94,0xf7,0x50};
		memcpy(createPrimaryIn.inPublic.publicArea.unique.ecc.x.t.buffer, onebuf, 32);
		createPrimaryIn.inPublic.publicArea.unique.ecc.y.t.size = 32;
		memcpy(createPrimaryIn.inPublic.publicArea.unique.ecc.y.t.buffer, twobuf, 32);
		*/
		createPrimaryIn.outsideInfo.t.size = 0;
		createPrimaryIn.creationPCR.count = 0;
	}
	/* call TPM2_CreatePrimary */
	if (rc == 0) {
		t0 = pbc_get_time();
		rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&createPrimaryOut,
			 (COMMAND_PARAMETERS *)&createPrimaryIn,
			 NULL,
			 TPM_CC_CreatePrimary,
			 auth_handle, NULL, 1,
			 TPM_RH_NULL, NULL, 0);
		t1 = pbc_get_time();
		*time_taken = t1 - t0;
	}
	/* Copy out the output I */
	if (rc == 0) {
		memcpy(I_x, createPrimaryOut.outPublic.publicArea.unique.ecc.x.t.buffer, 32);
		memcpy(I_y, createPrimaryOut.outPublic.publicArea.unique.ecc.y.t.buffer, 32);
	}
	/* Copy the primary key to static variable */
	if (rc == 0) {
		pkey_handle = createPrimaryOut.objectHandle;
	}
	/* output */
	if (rc != 0) {
		const char *msg;
		const char *submsg;
		const char *num;
		printf("createMemKeyP1: failed, rc %08x\n", rc);
		TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
		printf("%s%s%s\n", msg, submsg, num);
		rc = EXIT_FAILURE;
	}
	return rc;
}

TPM_RC createMemKeyP2(
			unsigned char *h1_x,
			unsigned char *h1_y,
			unsigned char *Rm_x,
			unsigned char *Rm_y,
			uint16_t *cntr,
			double *time_taken
		     )
{
	TPM_RC rc = 0;
	rc = commit_helper(
			h1_x, h1_y, NULL, NULL, NULL, NULL, NULL, NULL,
			Rm_x, Rm_y, cntr, time_taken);
	if (rc != 0) {
		const char *msg;
		const char *submsg;
		const char *num;
		printf("createMemKeyP2: failed, rc %08x\n", rc);
		TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
		printf("%s%s%s\n", msg, submsg, num);
		rc = EXIT_FAILURE;
	}
	return rc;
}

TPM_RC createMemKeyP3(  
			uint16_t cntr,
			uint32_t nonce,
			unsigned char *chm,
			unsigned char *ctm,
			unsigned char *sfm,
			double *time_taken
			)
{
	TPM_RC rc = 0;
	rc = sign_helper(cntr, nonce, chm, NULL, 0, ctm, sfm, time_taken);
	if (rc != 0) {
		const char *msg;
		const char *submsg;
		const char *num;
		printf("createMemKeyP3: failed, rc %08x\n", rc);
		TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
		printf("%s%s%s\n", msg, submsg, num);
		rc = EXIT_FAILURE;
	}
	return rc;
}

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
		   )
{
	TPM_RC rc = 0;
	rc = commit_helper(
			h1_x, h1_y, bj, d2j, Ej_x, Ej_y, S10_x, S10_y,
			S20_x, S20_y, cntr, time_taken);
	if (rc != 0) {
		const char *msg;
		const char *submsg;
		const char *num;
		printf("getSignKeyP1: failed, rc %08x\n", rc);
		TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
		printf("%s%s%s\n", msg, submsg, num);
		rc = EXIT_FAILURE;
	}
	return rc;
}

TPM_RC getSignKeyP2(
			uint16_t cntr,
			uint32_t nonce,
			unsigned char *ch0,
			unsigned char *cg0,
			unsigned char *sfg,
			double *time_taken
		   )
{
	TPM_RC rc = 0;
	rc = sign_helper(cntr, nonce, ch0, NULL, 0, cg0, sfg, time_taken);
	if (rc != 0) {
		const char *msg;
		const char *submsg;
		const char *num;
		printf("getSignKeyP2: failed, rc %08x\n", rc);
		TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
		printf("%s%s%s\n", msg, submsg, num);
		rc = EXIT_FAILURE;
	}
	return rc;
}

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
		   )
{
	TPM_RC rc = 0;
	rc = commit_helper(
			Dj_x, Dj_y, bi, d2i, Oi_x, Oi_y, S1i_x, S1i_y,
			S2i_x, S2i_y, cntr, time_taken);
	if (rc != 0) {
		const char *msg;
		const char *submsg;
		const char *num;
		printf("getSignKeyP3: failed, rc %08x\n", rc);
		TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
		printf("%s%s%s\n", msg, submsg, num);
		rc = EXIT_FAILURE;
	}
	return rc;
}

TPM_RC getSignKeyP4(
			uint16_t cntr,
			uint32_t nonce,
			unsigned char *chi,
			unsigned char *cgi,
			unsigned char *sfi,
			double *time_taken
		   )
{
	TPM_RC rc = 0;
	rc = sign_helper(cntr, nonce, chi, NULL, 0, cgi, sfi, time_taken);
	if (rc != 0) {
		const char *msg;
		const char *submsg;
		const char *num;
		printf("getSignKeyP4: failed, rc %08x\n", rc);
		TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
		printf("%s%s%s\n", msg, submsg, num);
		rc = EXIT_FAILURE;
	}
	return rc;
}

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
			double * time_taken
	     )
{
	TPM_RC rc = 0;
	rc = commit_helper(
			h1_x, h1_y, xjk, d2, E_x, E_y, S1s_x, S1s_y,
			S2s_x, S2s_y, cntr, time_taken);
	if (rc != 0) {
		const char *msg;
		const char *submsg;
		const char *num;
		printf("signP1: failed, rc %08x\n", rc);
		TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
		printf("%s%s%s\n", msg, submsg, num);
		rc = EXIT_FAILURE;
	}
	return rc;
}

TPM_RC signP2(
			uint16_t cntr,
			uint32_t nonce,
			unsigned char *chs,
			char *M,
			uint32_t M_len,
			unsigned char *sfs,
			unsigned char *cts,
			double *time_taken
	     )
{
	TPM_RC rc = 0;
	rc = sign_helper(cntr, nonce, chs, M, M_len, cts, sfs, time_taken);
	if (rc != 0) {
		const char *msg;
		const char *submsg;
		const char *num;
		printf("signP2: failed, rc %08x\n", rc);
		TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
		printf("%s%s%s\n", msg, submsg, num);
		rc = EXIT_FAILURE;
	}
	return rc;
}


TPM_RC flush_handles(void)
{
	TPM_RC				rc = 0;
        FlushContext_In 		flushContextIn;

	/* Flush the primary key */
	if (rc == 0) {
		flushContextIn.flushHandle = pkey_handle;
	}
	/* Call TPM2_FlushContext */
	if (rc == 0) {
		rc = TSS_Execute(tssContext,
			 NULL, 
			 (COMMAND_PARAMETERS *)&flushContextIn,
			 NULL,
			 TPM_CC_FlushContext,
			 TPM_RH_NULL, NULL, 0);
	}
	/* Flush the session */
	if (rc == 0) {
		flushContextIn.flushHandle = auth_handle;
	}
	if (rc == 0) {
		rc = TSS_Execute(tssContext,
			 NULL, 
			 (COMMAND_PARAMETERS *)&flushContextIn,
			 NULL,
			 TPM_CC_FlushContext,
			 TPM_RH_NULL, NULL, 0);
	}
	/* Delete the context */
	{  
		TPM_RC rc1 = TSS_Delete(tssContext);
		if (rc == 0) {
			rc = rc1;
		}
	}
	/* output */
	if (rc != 0) {
		const char *msg;
		const char *submsg;
		const char *num;
		printf("flush_handles: failed, rc %08x\n", rc);
		TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
		printf("%s%s%s\n", msg, submsg, num);
		rc = EXIT_FAILURE;
	}
	return rc;
}