#pragma once

#include <iostream>
#include <string>

using namespace std;

class Init {
public:
	static int openPortInFW(unsigned int port, string name, string protocol);
	static string getmac(unsigned char * mac);

	static string getTargetInfo(unsigned char * mac, unsigned long ip, unsigned short port);
};