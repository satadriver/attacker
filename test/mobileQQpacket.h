
#pragma once
#include <iostream>
#include "Packet.h"

using namespace std;




class MobileQQPacket {
public:
	static int processMobileQQPacket(LPIPHEADER pIPHdr, LPTCPHEADER pTcpHdr, char * packData, int packDataLen);
	static int mapclearer();

	static int init();
};