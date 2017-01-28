#include "laser_keygen.h"

int main()
{
	unsigned char * I_x = malloc(32 * sizeof(char));
	unsigned char * I_y = malloc(32 * sizeof(char));
	TPM_RC rc = createMemKeyP1(I_x, I_y);
	if (rc != 0)
	{
		printf("WHY!\n");
	}
	free(I_x);
	free(I_y);
	return 0;
}

TPM_RC createMemKeyP1(	
			unsigned char *I_x,
			unsigned char *I_y
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
	TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
	/* Start a TSS context */
	if (rc == 0) {
		rc = TSS_Create(&tssContext);
	}
	if (rc == 0) {
		rc = TSS_SetProperty(tssContext, TPM_INTERFACE_TYPE, "dev");
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
	/* Copy out the output I */
	if (rc == 0) {
		memcpy(I_x, createPrimaryOut.outPublic.publicArea.unique.ecc.x.t.buffer, 32);
		memcpy(I_y, createPrimaryOut.outPublic.publicArea.unique.ecc.y.t.buffer, 32);
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
