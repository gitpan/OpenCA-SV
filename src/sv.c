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

#include <openca/sv.h>

int main( int argc, char *argv[]) {

	PKCS7 *p7;
	PKCS7_SIGNER_INFO *si;
	X509_STORE_CTX cert_ctx;
	X509_STORE *cert_store=NULL;

	BIO *data = NULL, *p7bio=NULL;
	BIO *signature = NULL;

	int cmd=-1;
        char *infile=NULL;
        /* char *outfile=NULL; */
        char *certfile=NULL;
        char *keyfile=NULL;
        char *key=NULL;
	int nodetach=0;

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
		printVersion( bio_err, INFO );
		printf("ERROR: needed command and arguments missing\n\n");
		badops=1;
		goto badops;
	}

	if( ( cmd = getCommand( argc, argv ) ) == -1 ) {
		printVersion( bio_err, INFO );
		printf("ERROR: unknown command %s\n\n", argv[1] );
		badops=1;
		goto badops;
	}

	if( argc >= 1 ) {
		argc--;
		argv++;

		if( argc <= 1 )
		{
			printVersion( bio_err, INFO );
			printf("ERROR: needed at least one argument!\n\n" );
	                badops=1;
        	        goto badops;
		}
	}

	while (argc > 1) {
		argc--;
		argv++;
		if (strcmp(*argv,"-verbose") == 0)
                        {
			verbose=1;
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
			infile= *( ++argv );
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
		else if (strcmp(*argv,"-cert") == 0)
			{
                        if (--argc < 1) goto bad;
                        certfile = *( ++argv );
			}
		else if (strcmp(*argv,"-keyfile") == 0)
			{
                        if (--argc < 1) goto bad;
                        keyfile = *( ++argv );
			}
		else if (strcmp(*argv,"-key") == 0)
			{
                        if (--argc < 1) goto bad;
                        key = *( ++argv );
			}
		else if (strcmp(*argv,"-nd") == 0)
                        {
			nodetach=1;
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
			printVersion( bio_err, INFO );
                        BIO_printf(bio_err,"ERROR: unknown option %s\n\n",*argv);
                        badops=1;
                        break;
			}
	}

badops:
        if (badops) {
                for (pp=usage; (*pp != NULL); pp++)
                        BIO_printf(bio_err,*pp);
                        exit(1);
        }

	if( cmd == 1 ) {
		generateSignature( verbose, infile, outfile, certfile, keyfile, key, nodetach );
	} else if ( cmd == 2 )
		{
		verifySignature( verbose, infile, outfile, outdata, 
				chainVerify, datafile, certsdir, certsfile);
		}
	else if ( cmd == 3 )
		{
		sign2nd( verbose, infile, outfile, datafile, outdata );
		}
	exit(0);
}

