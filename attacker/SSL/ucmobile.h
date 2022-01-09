#pragma once

#include <iostream>
#include <string>
#include "sslPublic.h"

using namespace std;

class UCMobile {
public:

	static int isUCMobile(const char * url, const char * host);
	static int makeUpdateUrl(char * lpbuffer, int bufsize, int buflimit, LPSSLPROXYPARAM lpssl);



};