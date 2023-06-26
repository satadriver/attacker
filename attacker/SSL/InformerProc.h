#pragma once
#include "informerClient.h"
#include <WinSock2.h>
#include "InformerUdp.h"

#define INFORMER_SOCKET_TIMEOUT			1800000


#pragma pack(1)

typedef struct
{
	int sock;
	sockaddr_in sa;
	InformerClient *ssltarget;
	InformerUDP * udptarget;
}CONNECTION_INFO, *LPCONNECTION_INFO;

#pragma pack()

class InformerProc {
public:
	InformerClient *mClients;

	InformerUDP * mUdp;

	InformerProc * mInstance;

	InformerProc();
	~InformerProc();

	static int __stdcall informerProc(LPCONNECTION_INFO lpclientinfo);

	static int __stdcall informerListener(InformerProc*);
}; 