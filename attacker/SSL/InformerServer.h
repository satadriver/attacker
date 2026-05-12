#pragma once
#include "InformerInterface.h"
#include <WinSock2.h>
#include "InformerSvrUdp.h"

#define INFORMER_SOCKET_TIMEOUT			1800000


#pragma pack(1)

typedef struct
{
	int sock;
	sockaddr_in sa;
	InformerInterface*ssltarget;
	InformerSvrUDP* udptarget;
}CONNECTION_INFO, *LPCONNECTION_INFO;

#pragma pack()

class InformerServer {
public:
	InformerInterface *mClients;

	InformerSvrUDP* mUdp;

	InformerServer* mInstance;

	InformerServer();
	~InformerServer();

	static int __stdcall informerProc(LPCONNECTION_INFO lpclientinfo);

	static int __stdcall informerListener(InformerServer*);
}; 