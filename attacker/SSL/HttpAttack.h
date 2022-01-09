#pragma once

#ifndef HTTPATTACK_H_H_H
#define HTTPATTACK_H_H_H

#include <windows.h>
#include <iostream>
#include "sslPublic.h"

using namespace std;


class HttpAttack {
public:
	//static int isHttpRequestDataPacket(const char * url, const char * szdm, const char * httphdr,LPHTTPPROXYPARAM pstSSLProxyParam);
	//static int HttpRequestDataPacket(char * recvBuffer, int datasize);
	static int httpAttackPacket(char * lpbuf, int size, const char * url, const char * szdm,const char * httphdr,const char * httpdata,
		LPHTTPPROXYPARAM lphttp);
	static int sendAttackPacket(char * recvBuffer, int resultlen, const char * szdm, LPHTTPPROXYPARAM pstHttpProxyParam);

	static int httpAttackProc(char * recvBuffer, int &iCounter, LPHTTPPROXYPARAM pstHttpProxyParam);
};


#endif