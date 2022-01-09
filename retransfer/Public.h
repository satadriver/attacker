
#pragma once
#ifndef PUBLIC_H_H_H
#define PUBLIC_H_H_H

#include <windows.h>
#include <iostream>
#include "retransfer.h"

using namespace std;

#define SERVER_MUTEX_NAME "attacker.exe"



class Public {
public:

	static string Public::formatMAC(unsigned char mac[MAC_ADDRESS_SIZE]);
	static string Public::formatIP(unsigned int ip);
	
	static int Public::GBKToUTF8(char * inbuf, int inlen, char * outbuf, int outlen);

	static int getstring(char * flag, char * endflag, char * lpdata, char * lpdst, int start);
	static DWORD GetLocalIpAddress();

	static int WriteLogFile(char * szFileName, unsigned char * strBuffer, int iCounter, char * tag);
	//static DWORD Public::WriteLogFile(const char * pFileName, const char * pData, DWORD dwDataSize);
	//static DWORD WriteLogFile(const char * pData);
	static DWORD Public::WriteLogFile(const char * pData);
	

	static int removespace(char * src, char * dst);

	static string Public::getPluginPath();
	static string Public::getPluginPathWithoutSlash();
	static string Public::getpath();
	static string Public::getUserPluginPath(string username);

	static string Public::getUserUrl(string username, string filename);

	static string Public::getUserPluginPath();

	static string Public::getDateTime();

	static int Public::zipFile(string inzipfn, string srcfn, string zipfn);

	static DWORD Public::recorduser(unsigned long ip, string app);

	static int checkInstanceExist();

	

	static DWORD Public::recordipv6user(unsigned char* ipv6, string app);

	static string winPath2Linux(const char * winpath);

	static string Public::getLogPath();
	static string Public::getConfigPath();

	static int Public::GetInetIPAddress(char * szInetIP);
};

#endif