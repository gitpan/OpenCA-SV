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

#include <openca/sign2nd.h>

BIO *Sout = NULL;
BIO *p7bio = NULL;

int sign2nd( int verbose, char *infile, char *outfile, char *datafile,
				 int outdata ) {
	PKCS7 *p7;
	PKCS7 *new_p7;
	PKCS7_SIGNER_INFO *si;
	X509_STORE_CTX cert_ctx;
	X509_STORE *cert_store=NULL;

	BIO *data = NULL;
	BIO *signature = NULL;

	char buf[1024*4];
	int badops=0, err=0, version=0, i;

	STACK_OF(PKCS7_SIGNER_INFO) *sk;

	BIO_printf(bio_out, "verbose: %d\ninfile: %s\noutfile: %s\ndatafile: %s\noutdata: %d\n",
		verbose, infile, outfile, datafile, outdata );

	if(datafile) {
		data=BIO_new(BIO_s_file());
		if (!BIO_read_filename(data, datafile)) {
			BIO_printf( bio_err, "ERROR (1): Cannot access %s\n\n",
							datafile );
			exit(1);
		}
	};

	signature=BIO_new(BIO_s_file());
	if (infile == NULL) {
		BIO_set_fp(signature,stdin,BIO_NOCLOSE);
	} else {
		if (!BIO_read_filename(signature, infile)) {
			BIO_printf( bio_err, "ERROR (2): Cannot access %s\n\n",
							infile );
			exit(1);
		}
	}
		
	/* Load the PKCS7 object from a file */
	if ((p7=PEM_read_bio_PKCS7(signature,NULL,NULL,NULL)) == NULL) {
		err=1;
		goto err;
	};

	if( verbose ) {
		BIO_printf( bio_out, "Creating X509 context.\n" );
	};

	/* This stuff is being setup for certificate verification.
	 * When using SSL, it could be replaced with a 
	 * cert_stre=SSL_CTX_get_cert_store(ssl_ctx); */

	cert_store=X509_STORE_new();
	X509_STORE_set_default_paths(cert_store);

	ERR_clear_error();

	/* We need to process the data */
	if( PKCS7_get_detached(p7)) {
		BIO_printf( bio_out, "## This is a Detached Signature\n");
		if (data == NULL) {
			BIO_printf(bio_err, "ERROR: no data to add to signature\n");
			exit(1);
		}

	} else {
		BIO_printf(bio_err, "ERROR: non detached signature found!\n");
		exit(1);
	}

	/* Set the content of the signed to 'data' */
        /* 
	PKCS7_content_new(p7,NID_pkcs7_data);
        PKCS7_set_detached(p7,0);
	*/

	new_p7=PKCS7_new();
	PKCS7_set_type(new_p7,NID_pkcs7_signed);

	new_p7->d.sign->version = p7->d.sign->version ;
	new_p7->d.sign->md_algs = p7->d.sign->md_algs ;
	new_p7->d.sign->cert    = p7->d.sign->cert ;
	new_p7->d.sign->crl     = p7->d.sign->crl ;
	new_p7->d.sign->signer_info = p7->d.sign->signer_info ;

	PKCS7_content_new(new_p7,NID_pkcs7_data);

	if ((p7bio=PKCS7_dataInit(p7,NULL)) == NULL) { 
		BIO_printf( bio_err, "ERROR: cannto initialize new p7 data\n" );
		goto err;
	};

/*
        	PKCS7_set_detached(p7,0);
		p7bio=PKCS7_dataInit(p7,NULL);

		if( p7->d.sign->contents->d.data == NULL ) {
			BIO_printf( bio_err, "## d.data is actually NULL.\n" );
		}

		BIO_printf( bio_err, "## Adding DATA ... \n" );
*/

	        for (;;)
        	{
                	i=BIO_read(data,buf,sizeof(buf));
                	if (i <= 0) break;
                	BIO_write(p7bio,buf,i);
			BIO_printf( bio_out, "## read %d bytes of data\n", i );
        	}

		if( new_p7->d.sign->contents->d.data == NULL ) {
			BIO_printf( bio_err, "## d.data is actually NULL.\n" );
		}

		BIO_printf( bio_err, "## Zio Pover!\n" );
/*
        if ((p7bio=PKCS7_dataInit(p7,data)) == NULL) {
		BIO_printf( bio_err, "ERROR: setting p7bio to data" );
		goto err;
	}


        if (verbose)
                BIO_printf(bio_out,"Reading Data to be signed.\n");

        for (;;)
        {
                i=BIO_read(data,buf,sizeof(buf));
                if (i <= 0) break;
                BIO_write(p7bio,buf,i);
		BIO_printf( bio_out, "## read %d bytes of data\n", i );
        }
		BIO_printf( bio_out, "## read %d bytes of data\n", i );
*/

        if (!PKCS7_dataFinal(new_p7,p7bio)) {
		BIO_printf( bio_err, "ERROR: dataFinal returned 0\n");
		 goto err;
	};

        BIO_free(p7bio);

        Sout=BIO_new(BIO_s_file());
        if (outfile != NULL)
        {
                if (BIO_write_filename(Sout,outfile) <= 0)
                {
                        BIO_printf(bio_err,"Error writing file %s\n", outfile);
                        perror(outfile);
                        goto err;
                }
        }
        else
                BIO_set_fp(Sout,stdout,BIO_NOCLOSE|BIO_FP_TEXT);

        PEM_write_bio_PKCS7(Sout,new_p7);

/*
	if( outdata ) {

		if( verbose )
			BIO_printf( bio_out, "\n");

		BIO_printf( bio_out, "Stored PKCS7 data:\n" );
		do {
			i=BIO_read(p7bio,buf,sizeof(buf));
			buf[i] = '\x0';
			BIO_printf( bio_out, "%s", buf );
		} while ( i > 0 );
	}
*/

        PKCS7_free(p7);
        PKCS7_free(new_p7);
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
