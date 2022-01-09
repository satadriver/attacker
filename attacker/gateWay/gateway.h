#pragma once

#include <windows.h>
#include "../include\\pcap.h"
#include "../include\\pcap\\pcap.h"
#include <unordered_map>
#include "../Packet.h"


using namespace std;

#pragma pack(1)

typedef struct  
{
	DWORD cnt;

	MACHEADER mac;

	HEADER8021Q hdr8021_1;
	HEADER8021Q hdr8021_2;
	PPPOEHEADER pppoe;

	IPHEADER ip;

}GATEWAYPARAM,*LPGATEWAYPARAM;

#pragma pack()


class Gateway {
public:
	Gateway::Gateway(pcap_t * pcapt,DWORD serverip,DWORD localip,unsigned char * localmac);
	~Gateway();

	unordered_map <string, GATEWAYPARAM> mGatewayMap;

	pcap_t * mPcapt;

	DWORD mServerIP;

	DWORD mLocalIP;

	unsigned char mLocalMac[6];

	Gateway * mInstance;

	int mCnt;


	GATEWAYPARAM getGatewayParam();

	int getGateWay();

	static int __stdcall Gateway::sendServerUsername(Gateway * instance);

};


