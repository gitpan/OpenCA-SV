/* OpenCA SV Tool - Thanks to Eric Young for basic tool writing */
/* ============================================================ */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <openca/verify.h>

int verifySignature( int verbose, char *infile, char *outfile, int outdata,
                        int chainVerify, char *datafile, char *certsdir,
                        char *certsfile) {
	PKCS7 *p7;
	PKCS7_SIGNER_INFO *si;
	X509_STORE_CTX cert_ctx;
	X509_STORE *cert_store=NULL;

	BIO *data = NULL, *p7bio=NULL;
	BIO *signature = NULL;

	char *signaturefile = infile;

	char buf[1024*4];
	int badops=0, err=0, version=0, i;

	STACK_OF(PKCS7_SIGNER_INFO) *sk;

	if(datafile) {
		data=BIO_new(BIO_s_file());
		if (!BIO_read_filename(data, datafile)) {
			BIO_printf( bio_err, "ERROR: Cannot access %s\n\n",
							datafile );
			exit(1);
		}
	};

	signature=BIO_new(BIO_s_file());
	if (signaturefile == NULL) {
		BIO_set_fp(signature,stdin,BIO_NOCLOSE);
	} else {
		if (!BIO_read_filename(signature, signaturefile)) {
			BIO_printf( bio_err, "ERROR: Cannot access %s\n\n",
							signaturefile );
			exit(1);
		}
	}
		
	if (outfile != NULL) {
		if (!BIO_read_filename(bio_out, outfile)) {
			BIO_printf( bio_err, "ERROR: Cannot access %s\n\n",
							outfile );
			exit(1);
		}
	}
		
	/* Load the PKCS7 object from a file */
	if ((p7=PEM_read_bio_PKCS7(signature,NULL,NULL,NULL)) == NULL) {
		err=1;
		goto err;
	};

	/* This stuff is added for the OpenCA project by
	 * Massimiliano Pala <madwolf@openca.org>
	 */
	if( verbose ) {
		BIO_printf( bio_out, "Signature Informations (PKCS#7):\n" );
	};

	/* This stuff is being setup for certificate verification.
	 * When using SSL, it could be replaced with a 
	 * cert_stre=SSL_CTX_get_cert_store(ssl_ctx); */
	cert_store=X509_STORE_new();

	X509_STORE_set_default_paths(cert_store);
	X509_STORE_load_locations(cert_store,certsfile,certsdir);
	X509_STORE_set_verify_cb_func(cert_store,verify_callback);

	ERR_clear_error();

	/* We need to process the data */
	if ((PKCS7_get_detached(p7) || data)) {
		if (data == NULL) {
			printf("no data to verify the signature on\n");
			exit(1);
		} else {
			p7bio=PKCS7_dataInit(p7,data);
		}
	} else {
		p7bio=PKCS7_dataInit(p7,NULL);
	}

	/*
	## for (;;) {
        ## 	i=BIO_read(p7bio,buf,sizeof(buf));
        ## 	if (i <= 0) break;
        ## }
	*/

	/* We now have to 'read' from p7bio to calculate digests etc. */
	do {
		i=BIO_read(p7bio,buf,sizeof(buf));
	} while ( i > 0 );

	/* We can now verify signatures */
	sk=PKCS7_get_signer_info(p7);
	if (sk == NULL) {
		printf("there are no signatures on this data\n");
		exit(1);
	}

	/* Ok, first we need to, for each subject entry */
	for (i=0; i<sk_PKCS7_SIGNER_INFO_num(sk); i++) {
		ASN1_UTCTIME *tm;
		char *str1,*str2;

		si=sk_PKCS7_SIGNER_INFO_value(sk,i);
		i=PKCS7_dataVerify(cert_store,&cert_ctx,p7bio,p7,si);
		
		if ( ( i <= 0) && (chainVerify) ) {
			err=1;
			goto err;
		}
		
		if( verbose ) {
			if ((tm=get_signed_time(si)) != NULL) {
				BIO_printf(bio_out,"        Signed time: ");
				ASN1_UTCTIME_print(bio_out,tm);
				ASN1_UTCTIME_free(tm);
				BIO_printf(bio_out,"\n");
			}

			if (get_signed_seq2string(si,&str1,&str2)) {
				BIO_printf(bio_out,
					"        String 1 is %s\n",str1);
				BIO_printf(bio_out,
					"        String 2 is %s\n",str2);
			}
		}
	}

	if( verbose ) {
		BIO_printf(bio_out,"    Signature: Ok.\n");
	};

	if( outdata ) {
        	if ((PKCS7_get_detached(p7) || data)) {
                        p7bio=PKCS7_dataInit(p7,data);
        	} else {
                	p7bio=PKCS7_dataInit(p7,NULL);
        	}

		if( verbose )
			BIO_printf( bio_out, "\n");

		BIO_printf( bio_out, "Stored PKCS7 data:\n" );
		do {
			i=BIO_read(p7bio,buf,sizeof(buf));
			buf[i] = '\x0';
			BIO_printf( bio_out, "%s", buf );
		} while ( i > 0 );
	}

err:
	X509_STORE_free(cert_store);
	if( data ) BIO_free( data );
	if( signature ) BIO_free( signature );
	if( outfile ) BIO_free( bio_out );

	if( err == 0 )
		exit(0);

	ERR_load_crypto_strings();
	ERR_print_errors_fp(stderr);

	exit(1);
}
