#pragma once

#include <windows.h>

#include "sslPublic.h"
#include <iostream>

#include "..\\include\\openssl\\bio.h"
#include "..\\include\\openssl\\ssl.h"
#include "..\\include\\openssl\\err.h"
#include "..\\include\\openssl\\rsa.h"
#include "..\\include\\openssl\\pkcs12.h"



using namespace std;

class CertGenerate {
public:
	CertGenerate() {};
	~CertGenerate() {};

	void generateKeyPair(int bits);
	void generateCSR();
	int generateX509();
	bool checkX509Data(X509 *x509);
	void importCert(string cert, string pass, string path);
	void importCert(string cert, string path);
	void x509FromCertString(string cert, X509 **pX509);
	RSA *m_rsa;
	EVP_PKEY *m_pKey ;
	X509 * m_rootCert;
};