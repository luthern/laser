CC = /usr/bin/gcc
LIBS = -lgmp -lcrypto -lpbc -ltss
TSSDIR = /home/arias/ibmtss/utils/
PBCDIR = /usr/local/include/pbc/
PBCLIBDIR = /usr/local/lib/
CFLAGS = 	-DTPM_POSIX \
		-I$(TSSDIR) -I$(TSSDIR)tss2/ -I$(PBCDIR) -DTPM_TSS \
		-DTPM_INTERFACE_TYPE_DEFAULT="\"dev\"" -ggdb -Wall
LNFLAGS = 	-DTPM_POSIX		\
		-L$(TSSDIR)		\
		-L$(PBCLIBDIR)
TSS_HEADERS += 						\
		$(TSSDIR)tssauth.h 			\
		$(TSSDIR)tssccattributes.h 		\
		$(TSSDIR)tssdev.h  			\
		$(TSSDIR)tsssocket.h  			\
		$(TSSDIR)fail.h				\
		$(TSSDIR)tss2/tss.h			\
		$(TSSDIR)tss2/tsscryptoh.h		\
		$(TSSDIR)tss2/tsscrypto.h		\
		$(TSSDIR)tss2/tsserror.h		\
		$(TSSDIR)tss2/tssfile.h			\
		$(TSSDIR)tss2/tssmarshal.h		\
		$(TSSDIR)tss2/tssprint.h		\
		$(TSSDIR)tss2/tssproperties.h		\
		$(TSSDIR)tss2/tsstransmit.h		\
		$(TSSDIR)tss2/tssresponsecode.h		\
		$(TSSDIR)tss2/tssutils.h
PBC_HEADERS += 	$(wildcard $(PBCDIR)*.h)
	       
ALL = 		laser_ccs_tpm \
#		laser_platform \
#      		laser_issuer \

all:	$(ALL)

#CONSISTENT = 	laser_tpm.h 	\
	     	laser_hw_tpm.c 	\
	     	laser_utils.h

#laser_platform:		laser_platform.c
#			$(CC) $(CFLAGS) $(LNFLAGS) $(CONSISTENT) laser_platform.c $(LNALIBS) -o laser_platform $(LIBS)
#laser_issuer: 		laser_issuer.c
#			$(CC) $(CFLAGS) $(LNFLAGS) $(CONSISTENT) laser_issuer.c $(LNALIBS) -o laser_issuer $(LIBS)
laser_ccs_tpm:		laser_ccs_tpm.c
			$(CC) $(CFLAGS) $(LNFLAGS) laser.h laser_ccs_tpm.c laser_tpm.h laser_hw_tpm.c $(LNALIBS) -o ccs_exe $(LIBS)

clean:
	rm ccs_exe
