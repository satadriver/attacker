
#include "BaseSocket.h"
#include <WinSock2.h>
#include <stdio.h>
#include <ip6_misc.h>
#include <string>

#include<wininet.h>

#pragma comment(lib,"wininet.lib")

using namespace std;

SOCKET BaseSocket::listenUdpIPV6Port(unsigned int usPort) {
	int iRet = 0;

	int sockListen = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (sockListen <= 0)
	{
		printf("listenUdpIPV6Port port:%u socket error\n", usPort);
		return -1;
	}

	sockaddr_in6 saListen = { 0 };
	saListen.sin6_family = AF_INET6;
	saListen.sin6_port = ntohs(usPort);

// 	int bOptval = TRUE;
// 	iRet = setsockopt(sockListen, SOL_SOCKET, SO_REUSEADDR, (char *)&bOptval, sizeof(int));
// 	if (iRet < 0) {
// 		closesocket(sockListen);
// 		printf("listenUdpIPV6Port port:%u setsockopt error\n", usPort);
// 		return -1;
// 	}


	iRet = bind(sockListen, (sockaddr*)&saListen, sizeof(sockaddr_in6));
	if (iRet)
	{
		closesocket(sockListen);
		printf("listenUdpIPV6Port port:%u bind error\n", usPort);
		return -1;
	}

	return sockListen;
}

SOCKET BaseSocket::listenUdpPort(unsigned int usPort) {

	int iRet = 0;

	int sockListen = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sockListen <= 0)
	{
		printf("listenUdpPort port:%u socket error\n", usPort);
		return -1;
	}

	sockaddr_in saListen = { 0 };
	saListen.sin_addr.s_addr = INADDR_ANY;
	saListen.sin_family = AF_INET;
	saListen.sin_port = ntohs(usPort);

// 	int bOptval = TRUE;
// 	iRet = setsockopt(sockListen, SOL_SOCKET, SO_REUSEADDR, (char *)&bOptval, sizeof(int));
// 	if (iRet < 0) {
// 		closesocket(sockListen);
// 		printf("listenUdpPort port:%u setsockopt error\n", usPort);
// 		return -1;
// 	}


	iRet = bind(sockListen, (sockaddr*)&saListen, sizeof(sockaddr_in));
	if (iRet)
	{
		closesocket(sockListen);
		printf("listenUdpPort port:%u bind error\n", usPort);
		return -1;
	}

	return sockListen;
}


SOCKET BaseSocket::listenPort(unsigned long ip,unsigned int usPort) {

	int iRet = 0;

	int sockListen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sockListen < 0)
	{
		printf("BaseSocket port:%u socket error\n", usPort);
		return -1;
	}

	sockaddr_in saListen = { 0 };
	saListen.sin_addr.s_addr = ip;
	saListen.sin_family = AF_INET;
	saListen.sin_port = ntohs(usPort);

// 	int bOptval = TRUE;
// 	iRet = setsockopt(sockListen, SOL_SOCKET, SO_REUSEADDR, (char *)&bOptval, sizeof(int));
// 	if (iRet < 0) {
// 		closesocket(sockListen);
// 		printf("BaseSocket port:%u setsockopt error\n", usPort);
// 		return -1;
// 	}

	iRet = bind(sockListen, (sockaddr*)&saListen, sizeof(sockaddr_in));
	if (iRet < 0)
	{
		closesocket(sockListen);
		printf("BaseSocket port:%u bind error\n", usPort);
		return -1;
	}

	iRet = listen(sockListen, 16);
	if (iRet < 0)
	{
		closesocket(sockListen);
		printf("BaseSocket port:%u listen error\n", usPort);
		return -1;
	}

	return sockListen;	
}



SOCKET BaseSocket::listenPort(unsigned int usPort) {

	int iRet = 0;

	int sockListen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sockListen <= 0)
	{
		printf("BaseSocket port:%u socket error\n", usPort);
		return -1;
	}

	sockaddr_in saListen = { 0 };
	saListen.sin_addr.s_addr = INADDR_ANY;
	saListen.sin_family = AF_INET;
	saListen.sin_port = ntohs(usPort);

// 	int bOptval = TRUE;
// 	iRet = setsockopt(sockListen, SOL_SOCKET, SO_REUSEADDR, (char *)&bOptval, sizeof(int));
// 	if (iRet < 0) {
// 		closesocket(sockListen);
// 		printf("BaseSocket port:%u setsockopt error\n", usPort);
// 		return -1;
// 	}

	iRet = bind(sockListen, (sockaddr*)&saListen, sizeof(sockaddr_in));
	if (iRet )
	{
		closesocket(sockListen);
		printf("BaseSocket port:%u bind error:%d\n", usPort,WSAGetLastError());
		return -1;
	}

	iRet = listen(sockListen, 16);
	if (iRet )
	{
		closesocket(sockListen);
		printf("BaseSocket port:%u listen error\n", usPort);
		return -1;
	}

	return sockListen;
}



SOCKET BaseSocket::connectServer(unsigned long ip,int usPort) {
	int iRet = 0;

	int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET)
	{
		printf("BaseSocket socket port:%u error\n", usPort);
		return INVALID_SOCKET;
	}

	sockaddr_in sa = { 0 };
	sa.sin_addr.S_un.S_addr = ip;
	sa.sin_family = AF_INET;
	sa.sin_port = ntohs(usPort);

	iRet = connect(s,(sockaddr*)&sa,sizeof(sockaddr_in));
	if (iRet < 0)
	{
		closesocket(s);
		printf("BaseSocket connect port:%u error:%d\n", usPort,WSAGetLastError());
		return INVALID_SOCKET;
	}

	return s;
}



int BaseSocket::readUrl(string url,char * buffer,int bufsize) {

	HINTERNET internetopen = InternetOpenA("readUrl", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if (internetopen == NULL)
	{
		printf("InternetOpenA error:%u\r\n", WSAGetLastError());//12150
		return FALSE;
	}


	HINTERNET internetopenurl = InternetOpenUrlA(internetopen,url.c_str(),0,0, INTERNET_FLAG_RELOAD, 0);
	if (internetopenurl == NULL)
	{
		printf("InternetOpenUrlA error:%u\r\n", WSAGetLastError());//12150
		InternetCloseHandle(internetopen);
		return FALSE;
	}

	int size = 0;

	while (1)
	{
		DWORD byteread = 0;

		BOOL internetreadfile = InternetReadFile(internetopenurl, buffer, bufsize, &byteread);
		if (byteread <= 0) {
			break;
		}
		else {
			bufsize -= byteread;
			buffer += byteread;
			size += byteread;
		}
	}

	InternetCloseHandle(internetopenurl);

	InternetCloseHandle(internetopen);

	*(buffer + size) = 0;
	return size;
}