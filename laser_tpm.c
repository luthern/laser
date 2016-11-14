#include "laser_tpm.h"

static double t0 = 0;
static double t1 = 0;
//static char hostname[15] = "192.168.0.147";
static char hostname[15] = "127.0.0.1";
TPM_RC initTPM(void)
{
	TPM_SU		startupType = TPM_SU_CLEAR;
	TPM_RC		rc = 0;
	TSS_CONTEXT	*tssContext = NULL;
	Startup_In	in;

	TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
	/* Start a TSS Context */
	if (rc == 0) {
		rc = TSS_Create(&tssContext);
	}
	if (rc == 0) {
		TSS_SetProperty(tssContext, TPM_SERVER_NAME, hostname);
	}
	/* power off platform */
	if (rc == 0) {
		rc = TSS_TransmitPlatform(tssContext, TPM_SIGNAL_POWER_OFF,
			"TPM2_PowerOffPlatform");
	}
	/* power on platform */
	if (rc == 0) {
		rc = TSS_TransmitPlatform(tssContext, TPM_SIGNAL_POWER_ON,
			"TPM2_PowerOnPlatform");
	}
	/* power on NV space */
	if (rc == 0) {
		rc = TSS_TransmitPlatform(tssContext, TPM_SIGNAL_NV_ON,
			"TPM2_NvOnPlatform");
	}
	/* delete context */
	{
		TPM_RC rc1 = TSS_Delete(tssContext);
		if (rc == 0) {
			rc = rc1;
		}
	}
	/* Start a TSS Context */
	if (rc == 0) {
		rc = TSS_Create(&tssContext);
	}
	if (rc == 0) {
		TSS_SetProperty(tssContext, TPM_SERVER_NAME, hostname);
	}
	/* startup TPM */
	if (rc == 0) {
		in.startupType = startupType;
		rc = TSS_Execute(tssContext,
				 NULL,
				 (COMMAND_PARAMETERS *)&in,
				 NULL,
				 TPM_CC_Startup,
				 TPM_RH_NULL, NULL, 0);
	}
	/* delete context */
	{
		TPM_RC rc1 = TSS_Delete(tssContext);
		if (rc == 0) {
			rc = rc1;
		}
	}
	if (rc != 0) {
		const char *msg;
		const char *submsg;
		const char *num;
		printf("TPM Initialization: failed, rc %08x\n", rc);
		TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
		printf("%s%s%s\n", msg, submsg, num);
		rc = EXIT_FAILURE;
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
	TSS_CONTEXT			*tssContext = NULL;
	/* Table 50 - TPMI_RH_HIERARCHY primaryHandle */
	TPMI_RH_HIERARCHY		primaryHandle = TPM_RH_ENDORSEMENT;
	CreatePrimary_In		createPrimaryIn;
	CreatePrimary_Out		createPrimaryOut;
	StartAuthSession_In		startAuthSessionIn;
	StartAuthSession_Out		startAuthSessionOut;
        FlushContext_In 		flushContextIn;
	TPMI_ALG_HASH			halg = TPM_ALG_SHA256;
	// outputs and intermediates
	TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
	/* Start a TSS context */
	if (rc == 0) {
		rc = TSS_Create(&tssContext);
	}
	if (rc == 0) {
		TSS_SetProperty(tssContext, TPM_SERVER_NAME, hostname);
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

	/* Create the primary key from the DAASeed */
	if (rc == 0) {
		createPrimaryIn.primaryHandle = primaryHandle;
		createPrimaryIn.inSensitive.t.sensitive.data.t.size = 0;
		createPrimaryIn.inSensitive.t.sensitive.userAuth.t.size = 0;
		createPrimaryIn.inPublic.t.publicArea.type = TPM_ALG_ECC;
		createPrimaryIn.inPublic.t.publicArea.nameAlg = halg;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val = 0;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_FIXEDTPM;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_FIXEDPARENT;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_ADMINWITHPOLICY;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_NODA;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_RESTRICTED;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_DECRYPT;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_SIGN;
		createPrimaryIn.inPublic.t.publicArea.authPolicy.t.size = 0;	/* empty policy */
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_ECDAA;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.curveID = TPM_ECC_BN_P256;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.kdf.details.mgf1.hashAlg = halg;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.scheme.details.ecdaa.hashAlg = halg;
		createPrimaryIn.inPublic.t.publicArea.unique.ecc.x.t.size = 0;
		createPrimaryIn.inPublic.t.publicArea.unique.ecc.y.t.size = 0;
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
			 startAuthSessionOut.sessionHandle, NULL, 1,
			 TPM_RH_NULL, NULL, 0);
		t1 = pbc_get_time();
		*time_taken = t1 - t0;
	}
	/* Copy out the output I */
	if (rc == 0) {
		memcpy(I_x, createPrimaryOut.outPublic.t.publicArea.unique.ecc.x.t.buffer, 32);
		memcpy(I_y, createPrimaryOut.outPublic.t.publicArea.unique.ecc.y.t.buffer, 32);
	}
	/* Flush the primary key */
	if (rc == 0) {
		flushContextIn.flushHandle = createPrimaryOut.objectHandle;
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
	/*
	  Flush the session
	*/
	if (rc == 0) {
		flushContextIn.flushHandle = startAuthSessionOut.sessionHandle;
	}
	if (rc == 0) {
		rc = TSS_Execute(tssContext,
			 NULL, 
			 (COMMAND_PARAMETERS *)&flushContextIn,
			 NULL,
			 TPM_CC_FlushContext,
			 TPM_RH_NULL, NULL, 0);
	}
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
			uint16_t *commit_cntr,
			double *time_taken
		     )
{
	TPM_RC				rc = 0;
	TSS_CONTEXT			*tssContext = NULL;
	/* Table 50 - TPMI_RH_HIERARCHY primaryHandle */
	TPMI_RH_HIERARCHY		primaryHandle = TPM_RH_ENDORSEMENT;
	CreatePrimary_In		createPrimaryIn;
	CreatePrimary_Out		createPrimaryOut;
	Commit_In			commitIn;
	Commit_Out			commitOut;
	StartAuthSession_In		startAuthSessionIn;
	StartAuthSession_Out		startAuthSessionOut;
        FlushContext_In 		flushContextIn;
	TPMI_ALG_HASH			halg = TPM_ALG_SHA256;
	// outputs and intermediates
	TPMS_ECC_POINT			Rm;
	TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
	/* Start a TSS context */
	if (rc == 0) {
		rc = TSS_Create(&tssContext);
	}
	if (rc == 0) {
		TSS_SetProperty(tssContext, TPM_SERVER_NAME, hostname);
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

	/* Create the primary key from the DAASeed */
	if (rc == 0) {
		createPrimaryIn.primaryHandle = primaryHandle;
		createPrimaryIn.inSensitive.t.sensitive.data.t.size = 0;
		createPrimaryIn.inSensitive.t.sensitive.userAuth.t.size = 0;
		createPrimaryIn.inPublic.t.publicArea.type = TPM_ALG_ECC;
		createPrimaryIn.inPublic.t.publicArea.nameAlg = halg;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val = 0;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_FIXEDTPM;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_FIXEDPARENT;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_ADMINWITHPOLICY;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_NODA;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_RESTRICTED;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_DECRYPT;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_SIGN;
		createPrimaryIn.inPublic.t.publicArea.authPolicy.t.size = 0;	/* empty policy */
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_ECDAA;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.curveID = TPM_ECC_BN_P256;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.kdf.details.mgf1.hashAlg = halg;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.scheme.details.ecdaa.hashAlg = halg;
		createPrimaryIn.inPublic.t.publicArea.unique.ecc.x.t.size = 0;
		createPrimaryIn.inPublic.t.publicArea.unique.ecc.y.t.size = 0;
		createPrimaryIn.outsideInfo.t.size = 0;
		createPrimaryIn.creationPCR.count = 0;
	}
	/* call TPM2_CreatePrimary */
	if (rc == 0) {
		rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&createPrimaryOut,
			 (COMMAND_PARAMETERS *)&createPrimaryIn,
			 NULL,
			 TPM_CC_CreatePrimary,
			 startAuthSessionOut.sessionHandle, NULL, 1,
			 TPM_RH_NULL, NULL, 0);
	}
	/* input the point h1 and configure options for TPM2_Commit */
	if (rc == 0) {
		commitIn.signHandle = createPrimaryOut.objectHandle;
		commitIn.P1.t.size = 32 + 32 + 2 + 2;
		commitIn.P1.t.point.x.t.size = 32;
		commitIn.P1.t.point.y.t.size = 32;
		memcpy(commitIn.P1.t.point.x.t.buffer, h1_x, 32);
		memcpy(commitIn.P1.t.point.y.t.buffer, h1_y, 32);
		commitIn.s2.t.size = 0;
		commitIn.y2.t.size = 0;
	}
	/* call TPM2_Commit */
	if (rc == 0) {
		t0 = pbc_get_time();
		rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&commitOut,
			 (COMMAND_PARAMETERS *)&commitIn,
			 NULL,
			 TPM_CC_Commit,
			 startAuthSessionOut.sessionHandle, NULL, 1,
			 TPM_RH_NULL, NULL, 0);
		t1 = pbc_get_time();
		*time_taken = t1 - t0;
	}
	/* Copy out Rm */ 
	if (rc == 0) {
		Rm = commitOut.E.t.point;
		memcpy(Rm_x, Rm.x.t.buffer, Rm.x.t.size);
		memcpy(Rm_y, Rm.y.t.buffer, Rm.y.t.size);
		*commit_cntr = commitOut.counter;
	}
	/* Flush the primary key */
	if (rc == 0) {
		flushContextIn.flushHandle = createPrimaryOut.objectHandle;
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
	/*
	  Flush the session
	*/
	if (rc == 0) {
		flushContextIn.flushHandle = startAuthSessionOut.sessionHandle;
	}
	if (rc == 0) {
		rc = TSS_Execute(tssContext,
			 NULL, 
			 (COMMAND_PARAMETERS *)&flushContextIn,
			 NULL,
			 TPM_CC_FlushContext,
			 TPM_RH_NULL, NULL, 0);
	}
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
		printf("createMemKeyP2: failed, rc %08x\n", rc);
		TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
		printf("%s%s%s\n", msg, submsg, num);
		rc = EXIT_FAILURE;
	}
	return rc;
}

TPM_RC createMemKeyP3(  
			uint32_t nonce,
			uint16_t commit_cntr,
			unsigned char *chm,
			unsigned char *ctm,
			unsigned char *sfm,
			double *time_taken
			)
{
	TPM_RC				rc = 0;
	TSS_CONTEXT			*tssContext = NULL;
	/* Table 50 - TPMI_RH_HIERARCHY primaryHandle */
	TPMI_RH_HIERARCHY		primaryHandle = TPM_RH_ENDORSEMENT;
	CreatePrimary_In		createPrimaryIn;
	CreatePrimary_Out		createPrimaryOut;
	Sign_In				signIn;
	Sign_Out			signOut;
	StartAuthSession_In		startAuthSessionIn;
	StartAuthSession_Out		startAuthSessionOut;
        FlushContext_In 		flushContextIn;
	TPMI_ALG_HASH			halg = TPM_ALG_SHA256;
	// outputs and intermediates
	TPMT_HA				digest;
	uint32_t			sizeInBytes;
	uint16_t 			messageLength; 
	unsigned char*			message;

	TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
	/* Start a TSS context */
	if (rc == 0) {
		rc = TSS_Create(&tssContext);
	}
	if (rc == 0) {
		TSS_SetProperty(tssContext, TPM_SERVER_NAME, hostname);
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

	/* Create the primary key from the DAASeed */
	if (rc == 0) {
		createPrimaryIn.primaryHandle = primaryHandle;
		createPrimaryIn.inSensitive.t.sensitive.data.t.size = 0;
		createPrimaryIn.inSensitive.t.sensitive.userAuth.t.size = 0;
		createPrimaryIn.inPublic.t.publicArea.type = TPM_ALG_ECC;
		createPrimaryIn.inPublic.t.publicArea.nameAlg = halg;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val = 0;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_FIXEDTPM;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_FIXEDPARENT;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_ADMINWITHPOLICY;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_NODA;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_RESTRICTED;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_DECRYPT;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_SIGN;
		createPrimaryIn.inPublic.t.publicArea.authPolicy.t.size = 0;	/* empty policy */
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_ECDAA;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.curveID = TPM_ECC_BN_P256;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.kdf.details.mgf1.hashAlg = halg;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.scheme.details.ecdaa.hashAlg = halg;
		createPrimaryIn.inPublic.t.publicArea.unique.ecc.x.t.size = 0;
		createPrimaryIn.inPublic.t.publicArea.unique.ecc.y.t.size = 0;
		createPrimaryIn.outsideInfo.t.size = 0;
		createPrimaryIn.creationPCR.count = 0;
	}
	/* call TPM2_CreatePrimary */
	if (rc == 0) {
		rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&createPrimaryOut,
			 (COMMAND_PARAMETERS *)&createPrimaryIn,
			 NULL,
			 TPM_CC_CreatePrimary,
			 startAuthSessionOut.sessionHandle, NULL, 1,
			 TPM_RH_NULL, NULL, 0);
	}
	/* Produce digest that will be signed */ 
	if (rc == 0) {
		digest.hashAlg = halg;
		sizeInBytes = TSS_GetDigestSize(digest.hashAlg);
		messageLength = sizeInBytes + sizeof(uint32_t);
		message = malloc(messageLength);
		memcpy(message, chm, sizeInBytes);
		memcpy(message + sizeInBytes, &nonce, 4);
		rc = TSS_Hash_Generate(&digest, messageLength, message, 0, NULL);
		free(message);
	}
	/* Set up inputs for TPM2_Sign */
	if (rc == 0) {
		signIn.keyHandle = createPrimaryOut.objectHandle;
		signIn.inScheme.scheme = TPM_ALG_ECDAA;
		signIn.inScheme.details.ecdaa.count = commit_cntr;
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
			 startAuthSessionOut.sessionHandle, NULL, 1,
			 TPM_RH_NULL, NULL, 0);
		t1 = pbc_get_time();
		*time_taken = t1 - t0;
	}
	/* Copy out signature components */
	if (rc == 0) {
		memcpy(ctm, signOut.signature.signature.ecdaa.signatureR.t.buffer, 32);
		memcpy(sfm, signOut.signature.signature.ecdaa.signatureS.t.buffer, 32);
	}
	/* Flush the primary key */
	if (rc == 0) {
		flushContextIn.flushHandle = createPrimaryOut.objectHandle;
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
	/*
	  Flush the session
	*/
	if (rc == 0) {
		flushContextIn.flushHandle = startAuthSessionOut.sessionHandle;
	}
	if (rc == 0) {
		rc = TSS_Execute(tssContext,
			 NULL, 
			 (COMMAND_PARAMETERS *)&flushContextIn,
			 NULL,
			 TPM_CC_FlushContext,
			 TPM_RH_NULL, NULL, 0);
	}
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
	TPM_RC				rc = 0;
	TSS_CONTEXT			*tssContext = NULL;
	/* Table 50 - TPMI_RH_HIERARCHY primaryHandle */
	TPMI_RH_HIERARCHY		primaryHandle = TPM_RH_ENDORSEMENT;
	CreatePrimary_In		createPrimaryIn;
	CreatePrimary_Out		createPrimaryOut;
	Commit_In			commitIn;
	Commit_Out			commitOut;
	StartAuthSession_In		startAuthSessionIn;
	StartAuthSession_Out		startAuthSessionOut;
        FlushContext_In 		flushContextIn;
	TPMI_ALG_HASH			halg = TPM_ALG_SHA256;

	TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
	/* Start a TSS context */
	if (rc == 0) {
		rc = TSS_Create(&tssContext);
	}
	if (rc == 0) {
		TSS_SetProperty(tssContext, TPM_SERVER_NAME, hostname);
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

	/* Create the primary key from the DAASeed */
	if (rc == 0) {
		createPrimaryIn.primaryHandle = primaryHandle;
		createPrimaryIn.inSensitive.t.sensitive.data.t.size = 0;
		createPrimaryIn.inSensitive.t.sensitive.userAuth.t.size = 0;
		createPrimaryIn.inPublic.t.publicArea.type = TPM_ALG_ECC;
		createPrimaryIn.inPublic.t.publicArea.nameAlg = halg;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val = 0;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_FIXEDTPM;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_FIXEDPARENT;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_ADMINWITHPOLICY;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_NODA;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_RESTRICTED;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_DECRYPT;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_SIGN;
		createPrimaryIn.inPublic.t.publicArea.authPolicy.t.size = 0;	/* empty policy */
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_ECDAA;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.curveID = TPM_ECC_BN_P256;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.kdf.details.mgf1.hashAlg = halg;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.scheme.details.ecdaa.hashAlg = halg;
		createPrimaryIn.inPublic.t.publicArea.unique.ecc.x.t.size = 0;
		createPrimaryIn.inPublic.t.publicArea.unique.ecc.y.t.size = 0;
		createPrimaryIn.outsideInfo.t.size = 0;
		createPrimaryIn.creationPCR.count = 0;
	}
	/* call TPM2_CreatePrimary */
	if (rc == 0) {
		rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&createPrimaryOut,
			 (COMMAND_PARAMETERS *)&createPrimaryIn,
			 NULL,
			 TPM_CC_CreatePrimary,
			 startAuthSessionOut.sessionHandle, NULL, 1,
			 TPM_RH_NULL, NULL, 0);
	}
	/* input the point h1 and configure options for TPM2_Commit */
	if (rc == 0) {
		commitIn.signHandle = createPrimaryOut.objectHandle;
		commitIn.P1.t.size = 32 + 32 + 2 + 2;
		commitIn.P1.t.point.x.t.size = 32;
		commitIn.P1.t.point.y.t.size = 32;
		memcpy(commitIn.P1.t.point.x.t.buffer, h1_x, 32);
		memcpy(commitIn.P1.t.point.y.t.buffer, h1_y, 32);
		commitIn.s2.t.size = 32;
		memcpy(commitIn.s2.t.buffer, bj, 32);
		commitIn.y2.t.size = 32;
		memcpy(commitIn.y2.t.buffer, d2j, 32);
	}
	/* call TPM2_Commit */
	if (rc == 0) {
		t0 = pbc_get_time();
		rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&commitOut,
			 (COMMAND_PARAMETERS *)&commitIn,
			 NULL,
			 TPM_CC_Commit,
			 startAuthSessionOut.sessionHandle, NULL, 1,
			 TPM_RH_NULL, NULL, 0);
		t1 = pbc_get_time();
		*time_taken = t1 - t0;
	}
	/* Output */
	if (rc == 0) {	
		memcpy(Ej_x, commitOut.K.t.point.x.t.buffer, 32);
		memcpy(Ej_y, commitOut.K.t.point.y.t.buffer, 32);
		memcpy(S10_x, commitOut.L.t.point.x.t.buffer, 32);
		memcpy(S10_y, commitOut.L.t.point.y.t.buffer, 32);
		memcpy(S20_x, commitOut.E.t.point.x.t.buffer, 32);
		memcpy(S20_y, commitOut.E.t.point.y.t.buffer, 32);
		*cntr = commitOut.counter;
	}
	/* Flush the primary key */
	if (rc == 0) {
		flushContextIn.flushHandle = createPrimaryOut.objectHandle;
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
		flushContextIn.flushHandle = startAuthSessionOut.sessionHandle;
	}
	if (rc == 0) {
		rc = TSS_Execute(tssContext,
			 NULL, 
			 (COMMAND_PARAMETERS *)&flushContextIn,
			 NULL,
			 TPM_CC_FlushContext,
			 TPM_RH_NULL, NULL, 0);
	}
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
	TPM_RC				rc = 0;
	TSS_CONTEXT			*tssContext = NULL;
	/* Table 50 - TPMI_RH_HIERARCHY primaryHandle */
	TPMI_RH_HIERARCHY		primaryHandle = TPM_RH_ENDORSEMENT;
	CreatePrimary_In		createPrimaryIn;
	CreatePrimary_Out		createPrimaryOut;
	Sign_In				signIn;
	Sign_Out			signOut;
	StartAuthSession_In		startAuthSessionIn;
	StartAuthSession_Out		startAuthSessionOut;
        FlushContext_In 		flushContextIn;
	TPMI_ALG_HASH			halg = TPM_ALG_SHA256;
	uint32_t			sizeInBytes;
	uint16_t 			messageLength; 
	unsigned char			*message;
	TPMT_HA				digest;
	
	TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
	/* Start a TSS context */
	if (rc == 0) {
		rc = TSS_Create(&tssContext);
	}
	if (rc == 0) {
		TSS_SetProperty(tssContext, TPM_SERVER_NAME, hostname);
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
	/* Create the primary key from the DAASeed */
	if (rc == 0) {
		createPrimaryIn.primaryHandle = primaryHandle;
		createPrimaryIn.inSensitive.t.sensitive.data.t.size = 0;
		createPrimaryIn.inSensitive.t.sensitive.userAuth.t.size = 0;
		createPrimaryIn.inPublic.t.publicArea.type = TPM_ALG_ECC;
		createPrimaryIn.inPublic.t.publicArea.nameAlg = halg;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val = 0;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_FIXEDTPM;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_FIXEDPARENT;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_ADMINWITHPOLICY;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_NODA;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_RESTRICTED;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_DECRYPT;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_SIGN;
		createPrimaryIn.inPublic.t.publicArea.authPolicy.t.size = 0;	/* empty policy */
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_ECDAA;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.curveID = TPM_ECC_BN_P256;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.kdf.details.mgf1.hashAlg = halg;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.scheme.details.ecdaa.hashAlg = halg;
		createPrimaryIn.inPublic.t.publicArea.unique.ecc.x.t.size = 0;
		createPrimaryIn.inPublic.t.publicArea.unique.ecc.y.t.size = 0;
		createPrimaryIn.outsideInfo.t.size = 0;
		createPrimaryIn.creationPCR.count = 0;
	}
	/* call TPM2_CreatePrimary */
	if (rc == 0) {
		rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&createPrimaryOut,
			 (COMMAND_PARAMETERS *)&createPrimaryIn,
			 NULL,
			 TPM_CC_CreatePrimary,
			 startAuthSessionOut.sessionHandle, NULL, 1,
			 TPM_RH_NULL, NULL, 0);
	}
	/* Produce digest that will be signed */ 
	if (rc == 0) {
		messageLength = 36;
		message = malloc(messageLength);
		memcpy(message, ch0, 32);
		memcpy(message + 32, &nonce, 4);
		
		digest.hashAlg = halg;
		sizeInBytes = TSS_GetDigestSize(digest.hashAlg);
		rc = TSS_Hash_Generate(&digest, messageLength, message, 0, NULL);
		free(message);
	}
	/* Set up inputs for TPM2_Sign */
	if (rc == 0) {
		signIn.keyHandle = createPrimaryOut.objectHandle;
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
			 startAuthSessionOut.sessionHandle, NULL, 1,
			 TPM_RH_NULL, NULL, 0);
		t1 = pbc_get_time();
		*time_taken = t1 - t0;
	}
	/* Copy out signature components */
	if (rc == 0) {
		memcpy(cg0, signOut.signature.signature.ecdaa.signatureR.t.buffer, 32);
		memcpy(sfg, signOut.signature.signature.ecdaa.signatureS.t.buffer, 32);
	}
	/* Flush the primary key */
	if (rc == 0) {
		flushContextIn.flushHandle = createPrimaryOut.objectHandle;
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
		flushContextIn.flushHandle = startAuthSessionOut.sessionHandle;
	}
	if (rc == 0) {
		rc = TSS_Execute(tssContext,
			 NULL, 
			 (COMMAND_PARAMETERS *)&flushContextIn,
			 NULL,
			 TPM_CC_FlushContext,
			 TPM_RH_NULL, NULL, 0);
	}
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
	TPM_RC				rc = 0;
	TSS_CONTEXT			*tssContext = NULL;
	/* Table 50 - TPMI_RH_HIERARCHY primaryHandle */
	TPMI_RH_HIERARCHY		primaryHandle = TPM_RH_ENDORSEMENT;
	CreatePrimary_In		createPrimaryIn;
	CreatePrimary_Out		createPrimaryOut;
	Commit_In			commitIn;
	Commit_Out			commitOut;
	StartAuthSession_In		startAuthSessionIn;
	StartAuthSession_Out		startAuthSessionOut;
        FlushContext_In 		flushContextIn;
	TPMI_ALG_HASH			halg = TPM_ALG_SHA256;

	TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
	/* Start a TSS context */
	if (rc == 0) {
		rc = TSS_Create(&tssContext);
	}
	if (rc == 0) {
		TSS_SetProperty(tssContext, TPM_SERVER_NAME, hostname);
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

	/* Create the primary key from the DAASeed */
	if (rc == 0) {
		createPrimaryIn.primaryHandle = primaryHandle;
		createPrimaryIn.inSensitive.t.sensitive.data.t.size = 0;
		createPrimaryIn.inSensitive.t.sensitive.userAuth.t.size = 0;
		createPrimaryIn.inPublic.t.publicArea.type = TPM_ALG_ECC;
		createPrimaryIn.inPublic.t.publicArea.nameAlg = halg;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val = 0;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_FIXEDTPM;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_FIXEDPARENT;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_ADMINWITHPOLICY;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_NODA;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_RESTRICTED;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_DECRYPT;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_SIGN;
		createPrimaryIn.inPublic.t.publicArea.authPolicy.t.size = 0;	/* empty policy */
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_ECDAA;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.curveID = TPM_ECC_BN_P256;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.kdf.details.mgf1.hashAlg = halg;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.scheme.details.ecdaa.hashAlg = halg;
		createPrimaryIn.inPublic.t.publicArea.unique.ecc.x.t.size = 0;
		createPrimaryIn.inPublic.t.publicArea.unique.ecc.y.t.size = 0;
		createPrimaryIn.outsideInfo.t.size = 0;
		createPrimaryIn.creationPCR.count = 0;
	}
	/* call TPM2_CreatePrimary */
	if (rc == 0) {
		rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&createPrimaryOut,
			 (COMMAND_PARAMETERS *)&createPrimaryIn,
			 NULL,
			 TPM_CC_CreatePrimary,
			 startAuthSessionOut.sessionHandle, NULL, 1,
			 TPM_RH_NULL, NULL, 0);
	}
	/* input the point h1 and configure options for TPM2_Commit */
	if (rc == 0) {
		commitIn.signHandle = createPrimaryOut.objectHandle;
		commitIn.P1.t.size = 32 + 32 + 2 + 2;
		commitIn.P1.t.point.x.t.size = 32;
		commitIn.P1.t.point.y.t.size = 32;
		memcpy(commitIn.P1.t.point.x.t.buffer, Dj_x, 32);
		memcpy(commitIn.P1.t.point.y.t.buffer, Dj_y, 32);
		commitIn.s2.t.size = 32;
		memcpy(commitIn.s2.t.buffer, bi, 32);
		commitIn.y2.t.size = 32;
		memcpy(commitIn.y2.t.buffer, d2i, 32);
	}
	/* call TPM2_Commit */
	if (rc == 0) {
		t0 = pbc_get_time();
		rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&commitOut,
			 (COMMAND_PARAMETERS *)&commitIn,
			 NULL,
			 TPM_CC_Commit,
			 startAuthSessionOut.sessionHandle, NULL, 1,
			 TPM_RH_NULL, NULL, 0);
		t1 = pbc_get_time();
		*time_taken = t1 - t0;
	}
	/* Output */
	if (rc == 0) {	
		memcpy(Oi_x, commitOut.K.t.point.x.t.buffer, 32);
		memcpy(Oi_y, commitOut.K.t.point.y.t.buffer, 32);
		memcpy(S1i_x, commitOut.L.t.point.x.t.buffer, 32);
		memcpy(S1i_y, commitOut.L.t.point.y.t.buffer, 32);
		memcpy(S2i_x, commitOut.E.t.point.x.t.buffer, 32);
		memcpy(S2i_y, commitOut.E.t.point.y.t.buffer, 32);
		*cntr = commitOut.counter;
	}
	/* Flush the primary key */
	if (rc == 0) {
		flushContextIn.flushHandle = createPrimaryOut.objectHandle;
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
		flushContextIn.flushHandle = startAuthSessionOut.sessionHandle;
	}
	if (rc == 0) {
		rc = TSS_Execute(tssContext,
			 NULL, 
			 (COMMAND_PARAMETERS *)&flushContextIn,
			 NULL,
			 TPM_CC_FlushContext,
			 TPM_RH_NULL, NULL, 0);
	}
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
	TPM_RC				rc = 0;
	TSS_CONTEXT			*tssContext = NULL;
	/* Table 50 - TPMI_RH_HIERARCHY primaryHandle */
	TPMI_RH_HIERARCHY		primaryHandle = TPM_RH_ENDORSEMENT;
	CreatePrimary_In		createPrimaryIn;
	CreatePrimary_Out		createPrimaryOut;
	Sign_In			        signIn;
	Sign_Out			signOut;
	StartAuthSession_In		startAuthSessionIn;
	StartAuthSession_Out		startAuthSessionOut;
        FlushContext_In 		flushContextIn;
	TPMI_ALG_HASH			halg = TPM_ALG_SHA256;
	uint32_t			sizeInBytes;
	uint16_t 			messageLength; 
	unsigned char			*message;
	TPMT_HA				digest;
	
	TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
	/* Start a TSS context */
	if (rc == 0) {
		rc = TSS_Create(&tssContext);
	}
	if (rc == 0) {
		TSS_SetProperty(tssContext, TPM_SERVER_NAME, hostname);
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
	/* Create the primary key from the DAASeed */
	if (rc == 0) {
		createPrimaryIn.primaryHandle = primaryHandle;
		createPrimaryIn.inSensitive.t.sensitive.data.t.size = 0;
		createPrimaryIn.inSensitive.t.sensitive.userAuth.t.size = 0;
		createPrimaryIn.inPublic.t.publicArea.type = TPM_ALG_ECC;
		createPrimaryIn.inPublic.t.publicArea.nameAlg = halg;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val = 0;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_FIXEDTPM;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_FIXEDPARENT;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_ADMINWITHPOLICY;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_NODA;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_RESTRICTED;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_DECRYPT;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_SIGN;
		createPrimaryIn.inPublic.t.publicArea.authPolicy.t.size = 0;	/* empty policy */
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_ECDAA;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.curveID = TPM_ECC_BN_P256;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.kdf.details.mgf1.hashAlg = halg;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.scheme.details.ecdaa.hashAlg = halg;
		createPrimaryIn.inPublic.t.publicArea.unique.ecc.x.t.size = 0;
		createPrimaryIn.inPublic.t.publicArea.unique.ecc.y.t.size = 0;
		createPrimaryIn.outsideInfo.t.size = 0;
		createPrimaryIn.creationPCR.count = 0;
	}
	/* call TPM2_CreatePrimary */
	if (rc == 0) {
		rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&createPrimaryOut,
			 (COMMAND_PARAMETERS *)&createPrimaryIn,
			 NULL,
			 TPM_CC_CreatePrimary,
			 startAuthSessionOut.sessionHandle, NULL, 1,
			 TPM_RH_NULL, NULL, 0);
	}
	/* Produce digest that will be signed */ 
	if (rc == 0) {
		digest.hashAlg = halg;
		sizeInBytes = TSS_GetDigestSize(digest.hashAlg);
		messageLength = sizeInBytes + sizeof(uint32_t);
		message = malloc(messageLength);
		memcpy(message, chi, 32);
		memcpy(message + 32, &nonce, 4);
		rc = TSS_Hash_Generate(&digest, messageLength, message, 0, NULL);
		free(message);
	}
	/* Set up inputs for TPM2_Sign */
	if (rc == 0) {
		signIn.keyHandle = createPrimaryOut.objectHandle;
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
			 startAuthSessionOut.sessionHandle, NULL, 1,
			 TPM_RH_NULL, NULL, 0);
		t1 = pbc_get_time();
		*time_taken = t1 - t0;
	}
	/* Copy out signature components */
	if (rc == 0) {
		memcpy(cgi, signOut.signature.signature.ecdaa.signatureR.t.buffer, 32);
		memcpy(sfi, signOut.signature.signature.ecdaa.signatureS.t.buffer, 32);
	}
	/* Flush the primary key */
	if (rc == 0) {
		flushContextIn.flushHandle = createPrimaryOut.objectHandle;
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
	/*
	  Flush the session
	*/
	if (rc == 0) {
		flushContextIn.flushHandle = startAuthSessionOut.sessionHandle;
	}
	if (rc == 0) {
		rc = TSS_Execute(tssContext,
			 NULL, 
			 (COMMAND_PARAMETERS *)&flushContextIn,
			 NULL,
			 TPM_CC_FlushContext,
			 TPM_RH_NULL, NULL, 0);
	}
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
	TPM_RC				rc = 0;
	TSS_CONTEXT			*tssContext = NULL;
	/* Table 50 - TPMI_RH_HIERARCHY primaryHandle */
	TPMI_RH_HIERARCHY		primaryHandle = TPM_RH_ENDORSEMENT;
	CreatePrimary_In		createPrimaryIn;
	CreatePrimary_Out		createPrimaryOut;
	Commit_In			commitIn;
	Commit_Out			commitOut;
	StartAuthSession_In		startAuthSessionIn;
	StartAuthSession_Out		startAuthSessionOut;
        FlushContext_In 		flushContextIn;
	TPMI_ALG_HASH			halg = TPM_ALG_SHA256;

	TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
	/* Start a TSS context */
	if (rc == 0) {
		rc = TSS_Create(&tssContext);
	}
	if (rc == 0) {
		TSS_SetProperty(tssContext, TPM_SERVER_NAME, hostname);
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

	/* Create the primary key from the DAASeed */
	if (rc == 0) {
		createPrimaryIn.primaryHandle = primaryHandle;
		createPrimaryIn.inSensitive.t.sensitive.data.t.size = 0;
		createPrimaryIn.inSensitive.t.sensitive.userAuth.t.size = 0;
		createPrimaryIn.inPublic.t.publicArea.type = TPM_ALG_ECC;
		createPrimaryIn.inPublic.t.publicArea.nameAlg = halg;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val = 0;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_FIXEDTPM;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_FIXEDPARENT;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_ADMINWITHPOLICY;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_NODA;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_RESTRICTED;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_DECRYPT;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_SIGN;
		createPrimaryIn.inPublic.t.publicArea.authPolicy.t.size = 0;	/* empty policy */
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_ECDAA;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.curveID = TPM_ECC_BN_P256;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.kdf.details.mgf1.hashAlg = halg;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.scheme.details.ecdaa.hashAlg = halg;
		createPrimaryIn.inPublic.t.publicArea.unique.ecc.x.t.size = 0;
		createPrimaryIn.inPublic.t.publicArea.unique.ecc.y.t.size = 0;
		createPrimaryIn.outsideInfo.t.size = 0;
		createPrimaryIn.creationPCR.count = 0;
	}
	/* call TPM2_CreatePrimary */
	if (rc == 0) {
		rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&createPrimaryOut,
			 (COMMAND_PARAMETERS *)&createPrimaryIn,
			 NULL,
			 TPM_CC_CreatePrimary,
			 startAuthSessionOut.sessionHandle, NULL, 1,
			 TPM_RH_NULL, NULL, 0);
	}
	/* input the point h1 and configure options for TPM2_Commit */
	if (rc == 0) {
		commitIn.signHandle = createPrimaryOut.objectHandle;
		commitIn.P1.t.size = 32 + 32 + 2 + 2;
		commitIn.P1.t.point.x.t.size = 32;
		commitIn.P1.t.point.y.t.size = 32;
		memcpy(commitIn.P1.t.point.x.t.buffer, h1_x, 32);
		memcpy(commitIn.P1.t.point.y.t.buffer, h1_y, 32);
		commitIn.s2.t.size = 32;
		memcpy(commitIn.s2.t.buffer, xjk, 32);
		commitIn.y2.t.size = 32;
		memcpy(commitIn.y2.t.buffer, d2, 32);
	}
	/* call TPM2_Commit */
	if (rc == 0) {
		t0 = pbc_get_time();
		rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&commitOut,
			 (COMMAND_PARAMETERS *)&commitIn,
			 NULL,
			 TPM_CC_Commit,
			 startAuthSessionOut.sessionHandle, NULL, 1,
			 TPM_RH_NULL, NULL, 0);
		t1 = pbc_get_time();
		*time_taken = t1 - t0;
	}
	/* Output */
	if (rc == 0) {	
		memcpy(E_x, commitOut.K.t.point.x.t.buffer, 32);
		memcpy(E_y, commitOut.K.t.point.y.t.buffer, 32);
		memcpy(S1s_x, commitOut.L.t.point.x.t.buffer, 32);
		memcpy(S1s_y, commitOut.L.t.point.y.t.buffer, 32);
		memcpy(S2s_x, commitOut.E.t.point.x.t.buffer, 32);
		memcpy(S2s_y, commitOut.E.t.point.y.t.buffer, 32);
		*cntr = commitOut.counter;
	}
	/* Flush the primary key */
	if (rc == 0) {
		flushContextIn.flushHandle = createPrimaryOut.objectHandle;
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
		flushContextIn.flushHandle = startAuthSessionOut.sessionHandle;
	}
	if (rc == 0) {
		rc = TSS_Execute(tssContext,
			 NULL, 
			 (COMMAND_PARAMETERS *)&flushContextIn,
			 NULL,
			 TPM_CC_FlushContext,
			 TPM_RH_NULL, NULL, 0);
	}
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
		printf("signP2: failed, rc %08x\n", rc);
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
	TPM_RC				rc = 0;
	TSS_CONTEXT			*tssContext = NULL;
	/* Table 50 - TPMI_RH_HIERARCHY primaryHandle */
	TPMI_RH_HIERARCHY		primaryHandle = TPM_RH_ENDORSEMENT;
	CreatePrimary_In		createPrimaryIn;
	CreatePrimary_Out		createPrimaryOut;
	Sign_In			        signIn;
	Sign_Out			signOut;
	StartAuthSession_In		startAuthSessionIn;
	StartAuthSession_Out		startAuthSessionOut;
        FlushContext_In 		flushContextIn;
	TPMI_ALG_HASH			halg = TPM_ALG_SHA256;
	uint32_t			sizeInBytes;
	uint32_t 			messageLength; 
	unsigned char			*message;
	TPMT_HA				digest;
	
	TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
	/* Start a TSS context */
	if (rc == 0) {
		rc = TSS_Create(&tssContext);
	}
	if (rc == 0) {
		TSS_SetProperty(tssContext, TPM_SERVER_NAME, hostname);
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
	/* Create the primary key from the DAASeed */
	if (rc == 0) {
		createPrimaryIn.primaryHandle = primaryHandle;
		createPrimaryIn.inSensitive.t.sensitive.data.t.size = 0;
		createPrimaryIn.inSensitive.t.sensitive.userAuth.t.size = 0;
		createPrimaryIn.inPublic.t.publicArea.type = TPM_ALG_ECC;
		createPrimaryIn.inPublic.t.publicArea.nameAlg = halg;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val = 0;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_FIXEDTPM;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_FIXEDPARENT;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_ADMINWITHPOLICY;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_NODA;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_RESTRICTED;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val &= ~TPMA_OBJECT_DECRYPT;
		createPrimaryIn.inPublic.t.publicArea.objectAttributes.val |= TPMA_OBJECT_SIGN;
		createPrimaryIn.inPublic.t.publicArea.authPolicy.t.size = 0;	/* empty policy */
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_ECDAA;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.curveID = TPM_ECC_BN_P256;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.kdf.details.mgf1.hashAlg = halg;
		createPrimaryIn.inPublic.t.publicArea.parameters.eccDetail.scheme.details.ecdaa.hashAlg = halg;
		createPrimaryIn.inPublic.t.publicArea.unique.ecc.x.t.size = 0;
		createPrimaryIn.inPublic.t.publicArea.unique.ecc.y.t.size = 0;
		createPrimaryIn.outsideInfo.t.size = 0;
		createPrimaryIn.creationPCR.count = 0;
	}
	/* call TPM2_CreatePrimary */
	if (rc == 0) {
		rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&createPrimaryOut,
			 (COMMAND_PARAMETERS *)&createPrimaryIn,
			 NULL,
			 TPM_CC_CreatePrimary,
			 startAuthSessionOut.sessionHandle, NULL, 1,
			 TPM_RH_NULL, NULL, 0);
	}
	/* Produce digest that will be signed */ 
	if (rc == 0) {
		digest.hashAlg = halg;
		sizeInBytes = TSS_GetDigestSize(digest.hashAlg);
		messageLength = sizeInBytes + sizeof(uint32_t) + M_len;
		message = malloc(messageLength);
		memcpy(message, chs, sizeInBytes);
		memcpy(message + sizeInBytes, &nonce, sizeof(uint32_t));
		memcpy(message + sizeInBytes + sizeof(uint32_t), M, M_len);	
		rc = TSS_Hash_Generate(&digest, messageLength, message, 0, NULL);
		free(message);
	}
	/* Set up inputs for TPM2_Sign */
	if (rc == 0) {
		signIn.keyHandle = createPrimaryOut.objectHandle;
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
			 startAuthSessionOut.sessionHandle, NULL, 1,
			 TPM_RH_NULL, NULL, 0);
	
		t1 = pbc_get_time();
		*time_taken = t1 - t0;
	}

	/* Copy out signature components */
	if (rc == 0) {
		memcpy(cts, signOut.signature.signature.ecdaa.signatureR.t.buffer, 32);
		memcpy(sfs, signOut.signature.signature.ecdaa.signatureS.t.buffer, 32);
	}
	/* Flush the primary key */
	if (rc == 0) {
		flushContextIn.flushHandle = createPrimaryOut.objectHandle;
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
	/*
	  Flush the session
	*/
	if (rc == 0) {
		flushContextIn.flushHandle = startAuthSessionOut.sessionHandle;
	}
	if (rc == 0) {
		rc = TSS_Execute(tssContext,
			 NULL, 
			 (COMMAND_PARAMETERS *)&flushContextIn,
			 NULL,
			 TPM_CC_FlushContext,
			 TPM_RH_NULL, NULL, 0);
	}
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
		printf("signP2: failed, rc %08x\n", rc);
		TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
		printf("%s%s%s\n", msg, submsg, num);
		rc = EXIT_FAILURE;
	}
	return rc;

}
