#pragma once

#ifndef HTTPATTACK_H_H_H
#define HTTPATTACK_H_H_H

#include <windows.h>
#include <iostream>
#include "sslPublic.h"

using namespace std;


class HttpAttack {
public:

	static int httpAttackPacket(char * lpbuf, int size, const char * url, const char * host,const char * httphdr,const char * httpdata,
		LPHTTPPROXYPARAM hpp);
	static int sendAttackPacket(char * recvBuffer, int resultlen, const char * szdm, LPHTTPPROXYPARAM hpp);

	static int httpAttackProc(char * recvBuffer, int &iCounter, LPHTTPPROXYPARAM hpp);
};


#endif