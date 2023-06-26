
#pragma once
#ifndef TOOLS_H_H_H
#define TOOLS_H_H_H

#include <windows.h>
#include <iostream>

using namespace std;


#include <lm.h>

#define SYSTEM_VERSION_WIN9X	1
#define SYSTEM_VERSION_WIN2000	2
#define SYSTEM_VERSION_XP		3
#define SYSTEM_VERSION_VISTA	4
#define SYSTEM_VERSION_WIN7		5
#define SYSTEM_VERSION_WIN8		6
#define SYSTEM_VERSION_WIN10	7
#define SYSTEM_VERSION_UNKNOW	8

#pragma pack(1)
typedef struct
{
	char m_strSoftName[MAX_PATH];
	char m_strSoftVersion[MAX_PATH];
	char m_strInstallLocation[MAX_PATH];
	char m_strPublisher[MAX_PATH];
	char m_strInstallDate[MAX_PATH];
	DWORD m_strEstimatedSize;
	char m_strMainProPath[MAX_PATH];
	char m_strUninstallPth[MAX_PATH];
}SoftInfo, *pSoftInfo;
#pragma pack()

class Tools {
public:
	static int setNetworkParams();

	static int Tools::getNumberOfCPU();

	static int Tools::autorun(string username,string password,int cardno);

	static int GetWindowsVersion();

	static int GetCpuBits();

	static BOOL Tools::Is64bitSystem();

	static DWORD QueryRegistryValue(HKEY hMainKey, char * szSubKey, char * szKeyName, unsigned char * szKeyValue, int iCpuBits);

	static int Tools::addFirewallPort(unsigned int port, string name, string protocol);

	static int Tools::getInstallPath(int cpubits, string appname, string & installpath);

	static void closeException();
};

#endif