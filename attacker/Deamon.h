#pragma once

#ifndef DEAMON_H_H_H
#define DEAMON_H_H_H

#include <iostream>
#include <unordered_map>
#include "ssl/sslPublic.h"

using namespace std;

#define OUTPUT_TIMES 100
#define PEEK_BUF_SIZE 1

class Deamon {
public:

	unordered_map<LPHTTPPROXYPARAM, LPHTTPPROXYPARAM> gHttpDeamon;
	unordered_map<LPSSLPROXYPARAM, LPSSLPROXYPARAM> gSSLDeamon;

	CRITICAL_SECTION stcsHttp;
	CRITICAL_SECTION stcsSSL;

	int LOOP_TIME;
	int gOverTime;

	Deamon * mInstance;

	Deamon();
	~Deamon();

	int closeHTTP(LPHTTPPROXYPARAM lphttp);
	static int addHttp(LPHTTPPROXYPARAM);
	static int removeHttp(LPHTTPPROXYPARAM);
	static int __stdcall Deamon::clearHttp(Deamon*);

	int closeSSL(LPSSLPROXYPARAM lpssl);
	static int addSSL(LPSSLPROXYPARAM);
	static int removeSSL(LPSSLPROXYPARAM);
	static int __stdcall Deamon::clearSSL(Deamon*);
};

#endif