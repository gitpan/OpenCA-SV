/* OpenCA PKCS#7 tool - (c) 2000 by Massimiliano Pala and OpenCA Group */

#include <openca/tools.h>

getCommand ( int argc, char *argv[] ) {

	if( strcmp( argv[1], "sign" ) == 0 )
		{
		return(1);
		}
	else if ( strcmp( argv[1], "verify" ) == 0 )
		{
		return(2);
		}
	else if ( strcmp( argv[1], "sign2nd" ) == 0 )
		{
		return(3);
		}
	else
		{
		return( -1 );
		}
		
}

void printVersion( BIO *bio_err, char *INFO[] ) {
	BIO_printf( bio_err, "\n%s - Version %s\n", INFO[0], INFO[1] );
	BIO_printf( bio_err, "by %s\n", INFO[2] );
	BIO_printf( bio_err, "%s\n\n", INFO[3] );
}

