#!/usr/bin/perl

$|=1;

use OpenCA::OpenSSL;
my $openssl = new OpenCA::OpenSSL;

$openssl->setParams ( SHELL=>"/usr/local/ssl/bin/openssl",
		      CONFIG=>"/usr/local/mpcNET/stuff/openssl.cnf",
		      VERIFY=>"/usr/local/ssl/bin/verify",
		      SIGN=>"/usr/local/ssl/bin/sign" );

$openssl->setParams ( STDERR => "/dev/null" );

$sig = $openssl->sign( DATA_FILE=>"TEXT", CERT_FILE=>"03.pem",
		KEY_FILE=>"03_key.pem" );

print $openssl->verify( SIGNATURE=>"$sig", 
			DATA_FILE=>"TEXT",
			CA_CERT=>"cacert.pem",
			VERBOSE=>"1" );



exit 0; 

