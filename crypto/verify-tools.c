#include <stdio.h>
#include <stdlib.h>
#include <openssl/pkcs7.h>
#include <openssl/asn1_mac.h>

static int signed_string_nid= -1;
static signed_seq2string_nid= -1;

ASN1_UTCTIME *get_signed_time(PKCS7_SIGNER_INFO *si)
	{
	ASN1_TYPE *so;

	so=PKCS7_get_signed_attribute(si,NID_pkcs9_signingTime);
	if (so->type == V_ASN1_UTCTIME)
	    return so->value.utctime;
	return NULL;
	}

int get_signed_string(PKCS7_SIGNER_INFO *si, char *buf, int len)
	{
	ASN1_TYPE *so;
	ASN1_OCTET_STRING *os;
	int i;

	if (signed_string_nid == -1)
		signed_string_nid=
			OBJ_create("1.2.3.4.5","OID_example","Our example OID");
	/* To retrieve */
	so=PKCS7_get_signed_attribute(si,signed_string_nid);
	if (so != NULL)
		{
		if (so->type == V_ASN1_OCTET_STRING)
			{
			os=so->value.octet_string;
			i=os->length;
			if ((i+1) > len)
				i=len-1;
			memcpy(buf,os->data,i);
			return(i);
			}
		}
	return(0);
	}

/* For this case, I will malloc the return strings */
int get_signed_seq2string(PKCS7_SIGNER_INFO *si, char **str1, char **str2)
	{
	ASN1_TYPE *so;

	if (signed_seq2string_nid == -1)
		signed_seq2string_nid=
			OBJ_create("1.9.9999","OID_example","Our example OID");
	/* To retrieve */
	so=PKCS7_get_signed_attribute(si,signed_seq2string_nid);
	if (so && (so->type == V_ASN1_SEQUENCE))
		{
		ASN1_CTX c;
		ASN1_STRING *s;
		long length;
		ASN1_OCTET_STRING *os1,*os2;

		s=so->value.sequence;
		c.p=ASN1_STRING_data(s);
		c.max=c.p+ASN1_STRING_length(s);
		if (!asn1_GetSequence(&c,&length)) goto err;
		/* Length is the length of the seqence */

		c.q=c.p;
		if ((os1=d2i_ASN1_OCTET_STRING(NULL,&c.p,c.slen)) == NULL) 
			goto err;
		c.slen-=(c.p-c.q);

		c.q=c.p;
		if ((os2=d2i_ASN1_OCTET_STRING(NULL,&c.p,c.slen)) == NULL) 
			goto err;
		c.slen-=(c.p-c.q);

		if (!asn1_Finish(&c)) goto err;
		*str1=malloc(os1->length+1);
		*str2=malloc(os2->length+1);
		memcpy(*str1,os1->data,os1->length);
		memcpy(*str2,os2->data,os2->length);
		(*str1)[os1->length]='\0';
		(*str2)[os2->length]='\0';
		ASN1_OCTET_STRING_free(os1);
		ASN1_OCTET_STRING_free(os2);
		return(1);
		}
err:
	return(0);
	}
