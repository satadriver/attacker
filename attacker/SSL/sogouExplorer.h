#pragma once


#include <iostream>
#include "sslpublic.h"

using namespace std;

class SogouExplorer {
public:
	static int isSogouExplorer(const char * url, const char * host);
	static int replySogouExplorer(char * dstbuf, int dstbuflimit, LPHTTPPROXYPARAM lpssl);
};