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

/* Local Include */
#include <openca/callback.h>

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
