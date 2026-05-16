#pragma once

#ifndef HTTPATTACK_H_H_H
#define HTTPATTACK_H_H_H

#include <windows.h>
#include <iostream>
#include "sslPublic.h"

using namespace std;


class HttpAttack {
public:

	static int httpAttackPacket(char * buf, int size, const char * url, const char * host,const char * hdr,const char * data,LPHTTPPROXYPARAM hpp);
	
	static int sendAttackPacket(const char * buf, int len, LPHTTPPROXYPARAM hpp);

	static int httpAttackProc( char * buf, int &size, LPHTTPPROXYPARAM hpp);
};


#endif