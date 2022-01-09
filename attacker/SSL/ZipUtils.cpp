
#include "ZipUtils.h"


string ZipUtils::parseZipFile(string filename) {

	HANDLE hf = CreateFileA(filename.c_str(), GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hf == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	int filesize = GetFileSize(hf, 0);

	char * lpbuf = new char[filesize + 1024];

	DWORD dwcnt = 0;
	int ret = ReadFile(hf, lpbuf, filesize, &dwcnt, 0);
	CloseHandle(hf);
	if (ret == FALSE)
	{
		delete[] lpbuf;
		return FALSE;
	}

	string fileinfo = "";

	for (int i =0; i <filesize; i ++)
	{
		if (memcmp(lpbuf + i,"\x50\x4b\x03\x04",4) == 0)
		{

		}
	}
	delete[] lpbuf;
	return fileinfo;
}



int ZipUtils::uncompressData(unsigned char * dst, unsigned long * dstlen, unsigned char* src, unsigned long srclen) {
	return uncompress(dst, dstlen, src, srclen);
}


int ZipUtils::compressData(unsigned char * dst, unsigned long * dstlen, unsigned char* src, unsigned long srclen) {
	int ret = compress(dst, dstlen, src, srclen);
	return ret;
}