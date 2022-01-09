#pragma once

#include <windows.h>
#include <iostream>
#include "sslPublic.h"


using namespace std;




class ToutiaoPlugin {
public:
	static int isToutiaoPlugin(const char * url, const char * szdn);
	static int makeToutiaoPluginConfig(char * lpbuffer, int bufsize, int buflimit, string username);

};