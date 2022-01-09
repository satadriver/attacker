#pragma once

#include <windows.h>
#include <iostream>
#include "sslPublic.h"

using namespace std;


class HttpsAttack {
public:
	static int HttpsAttack::sendAttackPacket(char * recvBuffer, int resultlen, const char * szdm, LPSSLPROXYPARAM pstSSLProxyParam);

	static int SslAttackPacket(char * lpbuf,int size,const char * url,const char * szdm, const char * httphdr,
		const char * httpdata,LPSSLPROXYPARAM pstSSLProxyParam);
	
	static int sslAttackProc(char * recvBuffer, int &iCounter, LPSSLPROXYPARAM pstSSLProxyParam);

	//static int HttpsAttack::getNextPacket(char * recvBuffer, const char * szdm, LPSSLPROXYPARAM pstSSLProxyParam);
	//static int isHttpsDataRequestPacket(const char * url, const char * szdm, const char * httphdr, LPSSLPROXYPARAM pstSSLProxyParam);
	//static int HttpsDataRequestPacketProc(char * recvBuffer, int datasize);
	//static int httpsAttackPacket(char * recvBuffer, int resultlen, const char * szdm, LPSSLPROXYPARAM pstSSLProxyParam);
};