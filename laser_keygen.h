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
#include <openssl/sha.h>

TPM_RC createMemKeyP1(
			unsigned char *I_x,
			unsigned char *I_y
		   );
