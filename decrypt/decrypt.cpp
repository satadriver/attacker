
#include <windows.h>
#include <iostream>
#include "Shlwapi.h"

#pragma comment( lib, "Shlwapi.lib")
using namespace std;

/*
void CryptData(unsigned char * pdata, int size, unsigned char * pkey, int keylen) {

	for (int i = 0, j = 0; i < size;)
	{
		pdata[i] ^= pkey[j];
		j++;
		if (j == keylen)
		{
			j = 0;
		}
		i++;
	}
}

void getkey(unsigned char * key) {
	char *szrawkey = "i will win money";

	getDataMd5(szrawkey, lstrlenA(szrawkey), (char*)key, FALSE);

	//strncpy((char*)key, "i will win money", CRYPT_KEY_SIZE);
	return;
}

int fileDecryptReader(string filename, char ** lpbuf, int *bufsize) {
	int ret = 0;

	FILE * fp = fopen(filename.c_str(), "rb");
	if (fp <= 0)
	{
		printf("fileDecryptReader fopen file:%s error\r\n", filename.c_str());
		return FALSE;
	}

	ret = fseek(fp, 0, FILE_END);

	int filesize = ftell(fp);

	ret = fseek(fp, 0, FILE_BEGIN);

	*bufsize = filesize;

	*lpbuf = new char[filesize + 4096];

	ret = fread(*lpbuf, 1, filesize, fp);
	fclose(fp);
	if (ret <= FALSE)
	{
		delete lpbuf;
		return FALSE;
	}

	*(*lpbuf + filesize) = 0;

	char szfilename[1024];
	lstrcpyA(szfilename, filename.c_str());
	PathStripPathA(szfilename);
	if (strstr(szfilename, ".zip") || strstr(szfilename, ".apk") || strstr(szfilename, ".exe") || strstr(szfilename, ".dll"))
	{
		//for (int i = 0; i < sizeof(gCryptFnList) / sizeof(char*); i++)
		//{
		//if (lstrcmpiA(szfilename, gCryptFnList[i]) == 0) {
		if (memcmp(*lpbuf, "PK", 2) != 0 && memcmp(*lpbuf, "MZ", 2) != 0)
		{
			CryptData((unsigned char*)*lpbuf, filesize, gkey, CRYPT_KEY_SIZE);
		}
		//}
		//}
	}

	return filesize;
}
*/

int main() {

	string fn = "tvkplugin.zip";
	return 0;
}