#pragma once

#ifndef FILEOPER_H_H_H
#define FILEOPER_H_H_H

#include <windows.h>
#include <iostream>

using namespace std;

#define CRYPT_KEY_SIZE 16



class FileOper {
public:
	
	static int isExecutable(char * data);
	
	static int FileOper::fileWriter(string filename, const char * lpdate, int datesize, int clear);
	static	int FileOper::isFileExist(string filename);
	static	int FileOper::getFileSize(string filename);
	static	string FileOper::getDateTime();
	static	int FileOper::fileReader(string filename, char ** lpbuf, int *bufsize);
	static	int FileOper::fileWriter(string filename, const char * lpdate, int datesize);

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

};

#endif





















