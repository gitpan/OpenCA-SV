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

/* General definitions */
#ifdef SVERSION
#define VERSION SVERSION
#else
#define VERSION "Unknown\x0"
#endif

#include <stdio.h>
#include <openssl/bio.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include <openca/example.h>

int verify_callback(int ok, X509_STORE_CTX *ctx);

BIO *bio_err=NULL;
BIO *bio_out=NULL;

int verbose     = 0;
int chainVerify = 1;

static char *VER = VERSION;
static char *TITLE   = "SV Tool\x0";
static char *AUTHOR  = "Massimiliano Pala - OpenCA Project\x0";

static char *usage[]={
"usage: verify args\n",
"\n",
" -in file      - Input file\n",
" -out file     - Output file\n",
" -data file    - File containing signed data\n",
" -cf file      - CA's certificate file\n",
" -cd certsdir  - CAs' certificates directory\n",
" -print_data   - Print Signed Data to outfile\n",
" -no_chain     - Verifiy Just signature.\n",
" -verbose      - Verbose output\n",
" -version      - Print SV version\n",
"\n",
NULL
};

int main( int argc, char *argv[]) {

	PKCS7 *p7;
	PKCS7_SIGNER_INFO *si;
	X509_STORE_CTX cert_ctx;
	X509_STORE *cert_store=NULL;

	BIO *data = NULL, *p7bio=NULL;
	BIO *signature = NULL;

	char *datafile = NULL;
	char *outfile = NULL;
	char *signaturefile = NULL;

	char buf[1024*4];
	char **pp = NULL;
	int badops=0, outdata=0, err=0, version=0, i;

	 /* default certificates dir */
	/* char *certsdir="/usr/local/OpenCA/certs"; */

	 /* default certificates file */
	/* char *certsfile="/usr/local/OpenCA/cacert.pem"; */

	char *certsdir = NULL;
	char *certsfile = NULL;

	STACK_OF(PKCS7_SIGNER_INFO) *sk;

	if ((bio_err=BIO_new(BIO_s_file())) != NULL)
		BIO_set_fp(bio_err,stderr,BIO_NOCLOSE|BIO_FP_TEXT);

	bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);
	bio_out=BIO_new_fp(stdout,BIO_NOCLOSE);

#ifndef NO_MD5
        EVP_add_digest(EVP_md5());
#endif
#ifndef NO_SHA1
        EVP_add_digest(EVP_sha1());
#endif

	if( argc <= 1 ) {
		printf("ERROR: needed argument missing\n\n");
                for (pp=usage; (*pp != NULL); pp++)
                        BIO_printf(bio_err,*pp);
                        exit(1);
		exit(0);
	}

	while (argc > 1) {
		argc--;
		argv++;
		if (strcmp(*argv,"-verbose") == 0)
                        {
			verbose=1;
			}
		else if (strcmp(*argv,"-version") == 0)
                        {
			version=1;
			}
		else if (strcmp(*argv,"-print_data") == 0)
                        {
			outdata=1;
			}
		else if (strcmp(*argv,"-no_chain") == 0)
                        {
			chainVerify=0;
			}
		else if (strcmp(*argv,"-data") == 0)
			{
                        if (--argc < 1) goto bad;
			datafile= *( ++argv );
			}
		else if (strcmp(*argv,"-d") == 0)
			{
			/* Present for compatibility reasons ... */
                        if (--argc < 1) goto bad;
			datafile= *( ++argv );
			}
		else if (strcmp(*argv,"-in") == 0)
			{
                        if (--argc < 1) goto bad;
			signaturefile= *( ++argv );
			}
		else if (strcmp(*argv,"-out") == 0)
			{
                        if (--argc < 1) goto bad;
			outfile= *( ++argv );
			}
		else if (strcmp(*argv,"-cd") == 0)
			{
                        if (--argc < 1) goto bad;
                        certsdir = *(++argv);
			}
		else if (strcmp(*argv,"-cf") == 0)
			{
                        if (--argc < 1) goto bad;
                        certsfile = *( ++argv );
			}
		else if (strcmp(*argv,"-h") == 0)
			{
			   badops=1;
			   break;
			}
		else
			{
			if( argc == 2 ) {
				datafile = *argv;
				argc--;
				continue;
			}
bad:
                        BIO_printf(bio_err,"unknown option %s\n",*argv);
                        badops=1;
                        break;
			}
	}

	if (version) {
		BIO_printf( bio_err, "\n%s - Version %s\n", TITLE, VER );
		BIO_printf( bio_err, "by %s\n", AUTHOR );
		BIO_printf( bio_err, "GPL released\n\n");
		exit(0);
	}

        if (badops) {
                for (pp=usage; (*pp != NULL); pp++)
                        BIO_printf(bio_err,*pp);
                        exit(1);
        }

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

/* should be X509 * but we can just have them as char *. */
int verify_callback(int ok, X509_STORE_CTX *ctx)
	{
	char buf[256];
	X509 *err_cert;
	int err,depth;

	err_cert=X509_STORE_CTX_get_current_cert(ctx);
	err=	X509_STORE_CTX_get_error(ctx);
	depth=	X509_STORE_CTX_get_error_depth(ctx);
	
	X509_NAME_oneline(X509_get_subject_name(err_cert),buf,256);
	if( verbose ) {
		BIO_printf( bio_out, "    Depth: %d\n", depth );
		BIO_printf( bio_out, "        Serial Number: " );
		i2a_ASN1_INTEGER( bio_out, X509_get_serialNumber(err_cert) );
		BIO_printf( bio_out, "\n");
		BIO_printf( bio_out, "        Subject: %s\n", buf);
	}

	if (!ok && chainVerify) {
		if( verbose ) {
			BIO_printf(bio_err,"\nVerify Error %d: %s\n",err,
				X509_verify_cert_error_string(err));
		}

		if (depth < 6) {
			/* Hmmm???*/
			/*ok=1;*/
			X509_STORE_CTX_set_error(ctx,X509_V_OK);
		} else {
			ok=0;
			X509_STORE_CTX_set_error(ctx,
				X509_V_ERR_CERT_CHAIN_TOO_LONG);
		}
	}
	switch (ctx->error) {
		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
		     X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert),
		     						buf,256);
	     	     BIO_printf(bio_err,"issuer= %s\n",buf);

		     break;

	case X509_V_ERR_CERT_NOT_YET_VALID:
	case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
			BIO_printf(bio_err,"notBefore=");
			ASN1_UTCTIME_print(bio_err,
					X509_get_notBefore(ctx->current_cert));
			BIO_printf(bio_err,"\n");
			break;

	case X509_V_ERR_CERT_HAS_EXPIRED:
	case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
		BIO_printf(bio_err,"notAfter=");
		ASN1_UTCTIME_print(bio_err,
					X509_get_notAfter(ctx->current_cert));
		BIO_printf(bio_err,"\n");
		break;

	}


	if( verbose ) {
		BIO_printf(bio_err,"Verify Return: %d\n", ok);
		BIO_printf( bio_out, "    Signed Attributes:\n");
	};

	return(ok);
}
