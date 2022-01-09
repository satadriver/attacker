#pragma once

#include <iostream>

using namespace std;


class LeTVPlugin {
public:
	static int isletvPlugin(string url, string host);
	static int replyletvPlugin(char * dstbuf, int buflen, int buflimit, string username);
};