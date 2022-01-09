#pragma once

#include <windows.h>
#include <iostream>
#include "sslPublic.h"

using namespace std;




class Momo {
public:
	static int isMomoDns(string url, string host);

	static int makeMomoDns(char*recvBuffer, int len, int buflimit, LPHTTPPROXYPARAM http);

};
