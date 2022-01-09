

#include <winsock2.h>
#include <windows.h>
#include <iostream>
#include "Public.h"
#include "HttpUtils.h"

using namespace std;

#define ATTACK_LOG_FILENAME "log.txt"
#define ATTACKERROR_LOG_FILENAME "error.txt"

#define G_USERNAME "test20181205"


string Public::formatIP(unsigned int ip) {
	unsigned char cip[sizeof(unsigned int)];
	memmove(cip, &ip, sizeof(unsigned int));
	char szip[256];
	wsprintfA(szip, "%u.%u.%u.%u", cip[0], cip[1], cip[2], cip[3]);
	return szip;
}


string Public::formatMAC(unsigned char mac[MAC_ADDRESS_SIZE]) {

	char szmac[256];
	wsprintfA(szmac, "%02x-%02x-%02x-%02x-%02x-%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return szmac;
}


string Public::getDateTime() {
	SYSTEMTIME sttime = { 0 };
	GetLocalTime(&sttime);

	char sztime[MAX_PATH] = { 0 };
	int len = wsprintfA(sztime, "%u/%u/%u %u:%u:%u", sttime.wYear, sttime.wMonth, sttime.wDay, sttime.wHour, sttime.wMinute, sttime.wSecond);
	return string(sztime);
}


int Public::GBKToUTF8(char * inbuf,int inlen,char * outbuf,int outlen)
{
	int buflen = inlen + 16;
	WCHAR * str1 = new WCHAR[buflen];
	int translen = MultiByteToWideChar(CP_ACP, 0, inbuf, inlen, str1, buflen);
	*(WORD*)(str1 + translen) = 0;

	buflen = WideCharToMultiByte(CP_UTF8, 0, str1, -1, NULL, 0, NULL, NULL);
	if (buflen >= outlen)
	{
		delete [] str1;
		return 0;
	}

	translen = WideCharToMultiByte(CP_UTF8, 0, str1, -1, outbuf, outlen, NULL, NULL);
	*(WORD*)(outbuf + translen) = 0;

	delete[]str1;

	return translen;
}



int Public::getstring(char * flag,char * endflag, char * lpdata,char * lpdst,int start) {
	int flaglen = lstrlenA(flag);
	char * lphdr = strstr(lpdata, flag);
	if (lphdr)
	{
		if (start)
		{
			lphdr += flaglen;
		}
		
		char * lpend = strstr(lphdr, endflag);
		if (lpend)
		{
			int len = lpend - lphdr;
			memmove(lpdst, lphdr, len);
			*(lpdst + len) = 0;
			return len;
		}
	}
	return FALSE;
}


DWORD Public::GetLocalIpAddress()
{
	WORD wVersionRequested = MAKEWORD(2, 2);
	WSADATA wsaData = {0};
	if (WSAStartup(wVersionRequested, &wsaData) != 0)
	{
		return FALSE;
	}

	char local[MAX_PATH] = {0};
	int iRet = gethostname(local, sizeof(local));
	if (iRet )
	{
		return FALSE;
	}
	hostent* ph = gethostbyname(local);
	if (ph == NULL)
	{
		return FALSE;
	}

	in_addr addr = {0};
	memcpy(&addr, ph->h_addr_list[0], sizeof(in_addr)); 
	if (addr.S_un.S_addr == 0)
	{
		return FALSE;
	}

	char szip[MAX_PATH] = {0};
	unsigned char cip[4] = {0};
	memmove(cip,&addr.S_un.S_addr,4);
	int ret = wsprintfA(szip,"%u.%u.%u.%u",cip[0],cip[1],cip[2],cip[3]);
	printf("get ip from hostname:%s\r\n",szip);

	return addr.S_un.S_addr;
}


string Public::winPath2Linux(const char * winpath) {
	char linuxpath[1024];
	lstrcpyA(linuxpath, winpath);

	for ( int i = 0; i < lstrlenA(winpath); i++)
	{
		if (winpath[i] == '\\')
		{
			linuxpath[i] = '/';
		}
	}

	return string(linuxpath);
}

string Public::getpath() {
	char szcurdir[MAX_PATH] = { 0 };
	int ret = GetCurrentDirectoryA(MAX_PATH, szcurdir);
	return string(szcurdir) + "\\";
}

string Public::getPluginPath() {
	char szcurdir[MAX_PATH] = { 0 };
	int ret = GetCurrentDirectoryA(MAX_PATH, szcurdir);
	return string(szcurdir) + "\\" + "Plugin" + "\\";
}

string Public::getPluginPathWithoutSlash() {
	char szcurdir[MAX_PATH] = { 0 };
	int ret = GetCurrentDirectoryA(MAX_PATH, szcurdir);
	return string(szcurdir) + "\\" + "Plugin";
}

string Public::getUserPluginPath(string username) {
	char szcurdir[MAX_PATH] = { 0 };
	int ret = GetCurrentDirectoryA(MAX_PATH, szcurdir);
	return string(szcurdir) + "\\" + "Plugin" + "\\" + username + "\\";
}


string Public::getUserUrl(string username,string filename) {

	char buf[1024] = { 0 };
	buf[0] = '/';
	lstrcatA(buf, username.c_str());
	lstrcatA(buf, "/");
	lstrcatA(buf, filename.c_str());
	return string(buf);
	//string path = string("/").append(username).append("/").append(filename);
	//return path;
	//string path = (string("/") + username + string("/") + string(filename));
	//return path;
}

string Public::getUserPluginPath() {
	char szcurdir[MAX_PATH] = { 0 };
	int ret = GetCurrentDirectoryA(MAX_PATH, szcurdir);
	return string(szcurdir) + "\\" + "Plugin" + "\\" + G_USERNAME + "\\";
}

string Public::getLogPath() {
	char szcurdir[MAX_PATH] = { 0 };
	int ret = GetCurrentDirectoryA(MAX_PATH, szcurdir);
	return string(szcurdir) + "\\" + "output" + "\\";
}

string Public::getConfigPath() {
	char szcurdir[MAX_PATH] = { 0 };
	int ret = GetCurrentDirectoryA(MAX_PATH, szcurdir);
	return string(szcurdir) + "\\" + "config" + "\\";
}

int Public::WriteLogFile(char * pFileName, unsigned char * strBuffer, int iCounter, char * tag)
{
	string fn = getLogPath() + pFileName;
	HANDLE hFile = CreateFileA(fn.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0,
		OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	DWORD dwCnt = SetFilePointer(hFile, 0, 0, FILE_END);
	if (dwCnt == INVALID_SET_FILE_POINTER)
	{
		CloseHandle(hFile);
		return FALSE;
	}

	int iRet = WriteFile(hFile, tag, lstrlenA(tag), &dwCnt, 0);
	iRet = WriteFile(hFile, strBuffer, iCounter, &dwCnt, 0);
	CloseHandle(hFile);
	if (iRet == 0 || dwCnt != iCounter)
	{
		return FALSE;
	}

	return TRUE;


// 	string fn = getLogPath() + szFileName;
// 	int iRet = 0;
// 	FILE * fpFile = 0;
// 	iRet = fopen_s(&fpFile, fn.c_str(), "ab+");
// 	if (fpFile > 0)
// 	{
// 		iRet = fwrite(tag, 1, lstrlenA(tag), fpFile);
// 		iRet = fwrite(strBuffer, 1, iCounter, fpFile);
// 		fclose(fpFile);
// 		if (iRet != iCounter)
// 		{
// 			printf("写文件:%s错误\n", szFileName);
// 			return FALSE;
// 		}
// 		return TRUE;
// 	}
// 	else
// 	{
// 		printf("打开文件:%s错误\n", szFileName);
// 		return FALSE;
// 	}
// 	return FALSE;
}


// DWORD Public::WriteLogFile(const char * pFileName,const char * pData, DWORD dwDataSize)
// {
// 	string fn = getLogPath() + pFileName;
// 	HANDLE hFile = CreateFileA(fn.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, 0, 
// 		OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
// 	if (hFile == INVALID_HANDLE_VALUE)
// 	{
// 		return FALSE;
// 	}
// 
// 	DWORD dwCnt = SetFilePointer(hFile, 0, 0, FILE_END);
// 	if (dwCnt == INVALID_SET_FILE_POINTER)
// 	{
// 		CloseHandle(hFile);
// 		return FALSE;
// 	}
// 
// 	int iRet = WriteFile(hFile, pData, dwDataSize, &dwCnt, 0);
// 	CloseHandle(hFile);
// 	if (iRet == 0 || dwCnt != dwDataSize)
// 	{
// 		return FALSE;
// 	}
// 
// 	return TRUE;
// }





DWORD Public::WriteLogFile(const char * pData)
{
	string fn = getLogPath() + ATTACK_LOG_FILENAME;
	HANDLE hFile = CreateFileA(fn.c_str(),GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,0,
		OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,0);
	if(hFile == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	DWORD dwCnt = SetFilePointer(hFile,0,0,FILE_END);
	if (dwCnt == INVALID_SET_FILE_POINTER)
	{
		CloseHandle(hFile);
		return FALSE;
	}

	int len = lstrlenA(pData);
	int iRet = WriteFile(hFile,pData, len,&dwCnt,0);
	CloseHandle(hFile);
	if (iRet == 0 || dwCnt != len)
	{
		return FALSE;
	}

	return TRUE;
}

DWORD Public::recordipv6user(unsigned char* ipv6, string app)
{
	char log[1024];
	string time = Public::getDateTime();
	wsprintfA(log, "attack user:%s,app:%s,time:%s\r\n", HttpUtils::getIPv6str(ipv6).c_str(), app.c_str(), time.c_str());
	WriteLogFile((const char*)log);
	return TRUE;
}

DWORD Public::recorduser(unsigned long ip,string app)
{
	char log[1024];
	string time = Public::getDateTime();
	wsprintfA(log, "attack user:%s,app:%s,time:%s\r\n", HttpUtils::getIPstr(ip).c_str(), app.c_str(),time.c_str());
	WriteLogFile((const char*)log);
	return TRUE;
}
;





int Public::removespace(char * src, char * dst)
{
	int len = strlen(src);
	int i = 0, j = 0;
	for (; i < len; i++) {
		if (src[i] == ' ' || src[i] == 0x9) {
			continue;
		}
		else {
			dst[j] = src[i];
			j++;
		}
	}
	*(dst + j) = 0;
	return j;
}




int Public::checkInstanceExist()
{
	HANDLE hMutex = CreateMutexA(NULL, TRUE, SERVER_MUTEX_NAME);
	DWORD dwRet = GetLastError();
	if (hMutex)
	{
		if (ERROR_ALREADY_EXISTS == dwRet)
		{
			printf("mutex already exist,please shutdown the program and run one instance\r\n");
			CloseHandle(hMutex);
			return TRUE;
		}
		else
		{
			printf("program start running\r\n");
			return FALSE;
		}
	}
	else {
		printf("CreateMutexA error\r\n");
		return TRUE;
	}
}






int Public::GetInetIPAddress(char * szInetIP) {

	char * _szIp138Url = \
		"GET /ic.asp HTTP/1.1\r\n"\
		"Accept: text/html, application/xhtml+xml, image/jxr, */*\r\n"\
		"Referer: %s\r\n"\
		"Accept-Language: zh-CN\r\n"\
		"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 Edge/16.16299\r\n"
		"Accept-Encoding: gzip, deflate\r\n"\
		"Host: %s\r\n"\
		"Connection: Keep-Alive\r\n\r\n";

	char szIp138Host[] = { '2','0','1','8','.','i','p','1','3','8','.','c','o','m',0 };
	char szIp138Referer[] = { 'h','t','t','p',':','/','/','w','w','w','.','i','p','1','3','8','.','c','o','m','/',0 };

	//no netcard will cause this function return 0
	hostent * pHostent = gethostbyname(szIp138Host);
	if (pHostent == 0)
	{
		return FALSE;
	}
	ULONG  pPIp = *(DWORD*)((CHAR*)pHostent + sizeof(hostent) - sizeof(DWORD_PTR));
	ULONG  pIp = *(ULONG*)pPIp;
	DWORD dwip = *(DWORD*)pIp;
	sockaddr_in stServSockAddr = { 0 };
	stServSockAddr.sin_addr.S_un.S_addr = dwip;
	stServSockAddr.sin_port = ntohs(HTTP_PORT);
	stServSockAddr.sin_family = AF_INET;

	//SOCKET hSock = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
	SOCKET hSock = socket(AF_INET, SOCK_STREAM, 0);
	if (hSock == INVALID_SOCKET)
	{
		return FALSE;
	}

	int iRet = connect(hSock, (sockaddr*)&stServSockAddr, sizeof(sockaddr_in));
	if (iRet == INVALID_SOCKET)
	{

		closesocket(hSock);
		return FALSE;
	}

#define IP138_NETWORK_BUFSIZE 0X1000
	char szIp138Buf[IP138_NETWORK_BUFSIZE];
	iRet = wsprintfA(szIp138Buf, _szIp138Url, szIp138Referer, szIp138Host);
	iRet = send(hSock, szIp138Buf, iRet, 0);
	if (iRet <= 0)
	{

		closesocket(hSock);
		return FALSE;
	}

	iRet = recv(hSock, szIp138Buf, IP138_NETWORK_BUFSIZE, 0);
	closesocket(hSock);
	if (iRet <= 0)
	{
		return FALSE;
	}
	*(UINT*)(szIp138Buf + iRet) = 0;


	char szFlagHdr[] = { '<','c','e','n','t','e','r','>',0 };
	char szFlagEnd[] = { '<','/','c','e','n','t','e','r','>',0 };
	char * pInetIp = strstr(szIp138Buf, szFlagHdr);
	if (pInetIp)
	{
		pInetIp += lstrlenA(szFlagHdr);
		char * pInetIpEnd = strstr(pInetIp, szFlagEnd);
		if (pInetIpEnd)
		{
			RtlZeroMemory(szInetIP, sizeof(szInetIP));
			RtlMoveMemory(szInetIP, pInetIp, pInetIpEnd - pInetIp);
			return TRUE;
		}
	}

	return FALSE;
}