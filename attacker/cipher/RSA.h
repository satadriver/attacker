#pragma once

#include <iostream>
#include <windows.h>

using namespace std;


class RSACipher {
public:
	static unsigned char * RSACipher::rsaEncode(unsigned char *data, int datalen, unsigned char * out, int *outlen);
	static unsigned char * RSACipher::rsaDecode(unsigned char *data, int datalen, unsigned char * out, int *outlen);
	static int RSACipher::rsatest();

	static int RSACipher::rsaFileDecryptor(string filename);
};