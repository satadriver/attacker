


#pragma once

#include <iostream>
#include "sslpublic.h"

using namespace std;

class WPSPlugin {
public:
	static int isWpsPlugin(const char * url, const char * host);

	static int sendWpsPlugin(char * dstbuf, int dstbuflimit, string username);

	static int WPSPlugin::replyWpsPcUpdate(char * dstbuf, int dstbuflimit, string username);

	static int WPSPlugin::sendWpsPcUpdate(char * dstbuf, int dstbuflimit, string username);
};