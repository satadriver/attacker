
#include <openssl/sha.h>  
#include "../Utils/AscHex.h"
#include "sha1.h"
#include "../FileOper.h"

int MySha1::getsha1(const char* filename, char* out, int flag) {
	int ret = 0;
	char* data = 0;
	int filesize = 0;
	ret = FileOper::fileReader(filename, &data, &filesize);
	if (ret <= 0)
	{
		return false;
	}

	ret = getsha1((unsigned char*)data, filesize, out, flag);
	delete data;
	return ret;
}

int MySha1::getsha1(unsigned char* data, int len, char* out, int flag) {
	SHA_CTX c;
	unsigned char md[SHA_DIGEST_LENGTH];

	SHA1_Init(&c);

	SHA1_Update(&c, data, (unsigned long)len);

	SHA1_Final(&(md[0]), &c);

	return AscHex::hex2asc(md, SHA_DIGEST_LENGTH, flag, (unsigned char*)out);
}

