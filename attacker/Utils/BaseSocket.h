#pragma once
#include <string>

#include <windows.h>
#include <WinSock2.h>

using namespace std;

class BaseSocket {
public:
	static SOCKET listenPort(unsigned int port);
	static SOCKET listenPort(unsigned long ip,unsigned int usPort);

	static SOCKET connectServer(unsigned long ip, int usPort);

	static SOCKET BaseSocket::listenUdpPort(unsigned int usPort);

	static SOCKET BaseSocket::listenUdpIPV6Port(unsigned int usPort);

	static int readUrl(string url, char * buffer, int bufsize);
};