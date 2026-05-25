

#include "FileOper.h"
#include <time.h>
#include <Shlwapi.h>

#include <string>


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



int FileOper::fileReader(string filename, char** lpbuf, int* lpfs) {
	if (lpbuf == 0 || lpfs == 0) {
		return FALSE;
	}
	int ret = 0;

	FILE* fp = fopen(filename.c_str(), "rb");
	if (fp <= 0)
	{
		printf("fileReader fopen file:%s error\r\n", filename.c_str());
		return FALSE;
	}

	ret = fseek(fp, 0, FILE_END);

	unsigned long filesize = ftell(fp);

	ret = fseek(fp, 0, FILE_BEGIN);

	if (*lpbuf == 0 || *lpfs == 0) {
		*lpfs = filesize;
		*lpbuf = new char[filesize + 64];
		ret = fread(*lpbuf, 1, (size_t)filesize, fp);
		*(*lpbuf + filesize) = 0;
	}
	else {
		ret = fread(*lpbuf, 1, (size_t)*lpfs - 1, fp);
		lpbuf[*lpfs - 1] = 0;
	}

	fclose(fp);

	return filesize;
}



int FileOper::fileWriter(string filename, const char* lpdata, int size) {
	int ret = 0;

	FILE* fp = fopen(filename.c_str(), "ab+");
	if (fp <= 0)
	{
		printf("fileReader fopen file:%s error\r\n", filename.c_str());
		return FALSE;
	}

	ret = fwrite(lpdata, 1, size, fp);
	fclose(fp);
	if (ret == FALSE)
	{
		return FALSE;
	}

	return size;
}


int FileOper::fileWriter(string filename, const char* data, int datasize, int clear) {
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

	ret = fwrite(data, 1, datasize, fp);
	fclose(fp);
	if (ret == FALSE)
	{
		return FALSE;
	}

	return datasize;
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




int FileOper::searchDir(CHAR* srcpath, vector<string>& strs) {

	int result = 0;

	CHAR path[MAX_PATH];
	lstrcpyA(path, srcpath);

	int pathlen = lstrlenA(path);
	if (path[pathlen - 1] == '\\')
	{

	}
	else {
		lstrcatA(path, "\\");
	}

	const CHAR* allfiles = "*.*";
	string searchpath = string(path) + allfiles;

	int cnt = 0;

	WIN32_FIND_DATAA finddata = { 0 };
	HANDLE hf = FindFirstFileA(searchpath.c_str(), &finddata);
	if (hf == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	do
	{
		if (finddata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			if (lstrcmpiA(finddata.cFileName, ".") == 0 || lstrcmpiA(finddata.cFileName, "..") == 0)
			{

			}
			else {
				CHAR nextpath[MAX_PATH];
				lstrcpyA(nextpath, path);
				lstrcatA(nextpath, finddata.cFileName);
				strs.push_back(finddata.cFileName);
				cnt++;
			}
		}
		else if (finddata.dwFileAttributes & FILE_ATTRIBUTE_ARCHIVE)
		{
			CHAR filename[MAX_PATH];
			lstrcpyA(filename, path);
			lstrcatA(filename, finddata.cFileName);
		}

		result = FindNextFileA(hf, &finddata);
	} while (result);

	FindClose(hf);

	return cnt;
}


int FileOper::delFolder(CHAR* srcpath) {

	int result = 0;

	CHAR path[MAX_PATH];
	lstrcpyA(path, srcpath);

	int pathlen = lstrlenA(path);
	if (path[pathlen - 1] == '\\')
	{

	}
	else {
		lstrcatA(path, "\\");
	}

	const CHAR* allfiles = "*.*";
	string searchpath = string(path) + allfiles;

	int cnt = 0;

	WIN32_FIND_DATAA finddata;
	HANDLE hf = FindFirstFileA(searchpath.c_str(), &finddata);
	if (hf == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	do
	{
		if (finddata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			if (lstrcmpiA(finddata.cFileName, ".") == 0 || lstrcmpiA(finddata.cFileName, "..") == 0)
			{

			}
			else {
				CHAR nextpath[MAX_PATH];
				lstrcpyA(nextpath, path);
				lstrcatA(nextpath, finddata.cFileName);
				cnt += delFolder(nextpath);
				cnt += DeleteFileA(nextpath);
				//RemoveDirectoryW(nextpath);
			}
		}
		else if (finddata.dwFileAttributes & FILE_ATTRIBUTE_ARCHIVE)
		{
			CHAR filename[MAX_PATH];
			lstrcpyA(filename, path);
			lstrcatA(filename, finddata.cFileName);

			cnt += DeleteFileA(filename);
			cnt++;
		}

		result = FindNextFileA(hf, &finddata);
	} while (result);

	FindClose(hf);

	return cnt;
}