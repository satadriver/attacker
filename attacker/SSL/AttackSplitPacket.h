#pragma once
#include "sslPublic.h"

class AttackSplitPacket {
public:
	static int splitPacket(char * recvbuf, int &icount, LPHTTPPROXYPARAM lphttp,
		string & httphdr,char ** httpdata,string &url,string & host,int &port);
	static int splitPacket(char * recvbuf, int &icount, LPSSLPROXYPARAM lpssl,
		string & httphdr,char ** httpdata,string &url,string &host,int &port);
};