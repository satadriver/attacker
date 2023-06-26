
#pragma once
#ifndef PUBLIC_H_H_H
#define PUBLIC_H_H_H

#include <vector>
#include <windows.h>
#include <iostream>
#include "cipher/zip.h"

using namespace std;

#define ATTACKER_MUTEX_NAME "global_attacker"



class Public {
public:

	static int getstring(char* flag, char* endflag, char* lpdata, char* lpdst, int start);

	static DWORD GetLocalIpAddress();

	static int WriteLogFile(const char* szFileName, unsigned char* strBuffer, int iCounter, const char* tag);

	static DWORD Public::WriteLogFile(const char* pFileName, const char* pData, int datasize);

	static DWORD WriteLogFile(const char* pData);

	static DWORD Public::log(const char* format, ...);

	static int removespace(char* src, char* dst);

	static string Public::getPluginPath();

	static string Public::getPluginPathWithoutSlash();

	static string Public::getpath();

	static string Public::getLogPath();

	static string Public::getUserPluginPath(string username);

	static string Public::getUserUrl(string username, string filename);

	static string Public::getDefaultUserPluginPath();

	static string Public::getDateTime();

	static int Public::zipFile(string inzipfn, string srcfn, string zipfn);

	static int Public::zipFiles(vector<string> inzipfns, vector<string> srcfns, string zipfn);

	static DWORD checkInstanceExist();

	static DWORD Public::recorduser(unsigned long ip, string app);

	static DWORD Public::recordipv6user(unsigned char* ipv6, string app);

	static string winPath2Linux(const char* winpath);

	static int Public::isipstr(const char* str);

	static int getNameAndPathFromUrl(string url, string& filename, string& path);

	static string Public::getNameFromFullPath(string fullpath);

	static string Public::getPathFromFullPath(string fullpath);

	static int isPrivateIPAddress(string ip);

	static int isPrivateIPAddress(DWORD ip);
};

#endif