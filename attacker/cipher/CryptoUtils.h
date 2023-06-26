#pragma once


#ifndef CRYPTUTILS_H_H_H
#define CRYPTUTILS_H_H_H

#include <windows.h>
#include "../include/openssl/md5.h"
#include <iostream>



using namespace std;

typedef unsigned int uint;

class CryptoUtils {
public:

	static int getUpdateFileMd5(string filename, char * szmd5, unsigned char * hexmd5, int lowercase);
	static int getDataMd5(char * lpdata, int size, char * szmd5, int lowercase);

	static uint CryptoUtils::crc32(uint crc, char *buff, int len);

	static string CryptoUtils::FileCrc32(string ascfile, int len,int islowercase);

	static void CryptoUtils::make_table();

	static uint64_t CryptoUtils::crc64(uint64_t crc, const unsigned char *s, uint64_t l);
	static string CryptoUtils::FileCrc64(string ascfile, int len, int islowercase);

};


#endif

