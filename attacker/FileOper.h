#pragma once

#ifndef FILEOPER_H_H_H
#define FILEOPER_H_H_H

#include <vector>
#include <windows.h>
#include <iostream>

using namespace std;

#define CRYPT_KEY_SIZE 16



class FileOper {
public:
	
	static int isExecutable(char * data);
	static int GetFileType(string filename);
	static int fileWriter(string filename, const char * lpdate, int datesize, int clear);
	static	int isFileExist(string filename);
	static	int getFileSize(string filename);
	static	string getDateTime();
	static	int fileReader(string filename, char ** lpbuf, int*bufsize);
	static	int fileWriter(string filename, const char * lpdate, int datesize);

	static DWORD GetCryptKey(unsigned char * pKey);
	static void CryptData(unsigned char * pdata, int size, unsigned char * pkey, int keylen);
	static void getkey(unsigned char * key);

	static int fileEncryptor(string path,unsigned char * key, int keylen);

	static int fileDecryptReader(string filename, char **lpdata,int * filesize);

	static int offsetFileDecryptReader(string filename, char ** lpbuf, int offset, int *bufsize);

	static int checkFileCryption(string path);

	static int FileOper::fileDecryptWriter(string filename, string dstfn);
	static int FileOper::initKey();

	static int FileOper::fileDecryptor(string path);

	static int searchDir(CHAR* srcpath, vector<string>& strs);
	static int delFolder(CHAR* path);

	static int FileSearchSet(string fn, char* tag, int taglen, char* data, int size);
};

#endif





















