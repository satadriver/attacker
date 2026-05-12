#include <conio.h>
#include "InformerSvrUdp.h"
#include "informerServer.h"
#include "../utils/BaseSocket.h"
#include "../attacker.h"
#include "../informer.h"
#include "InformerInterface.h"
#include "sslPublic.h"
#include "../HttpUtils.h"
#include "../DnsUtils/dnsUtils.h"
#include "../Utils/Tools.h"



InformerSvrUDP::InformerSvrUDP(InformerInterface*client) {
	mClients = client;
	mUdp = this;
	CloseHandle(CreateThread(0, 0, (LPTHREAD_START_ROUTINE)informerUdpListener, this, 0, 0));
}


InformerSvrUDP::~InformerSvrUDP() {
	delete mClients;
}




int __stdcall InformerSvrUDP::informerUdpListener(InformerSvrUDP* instance) {
	int ret = 0;

	int targetServerSock = BaseSocket::listenUdpPort(INFORMER_PORT);
	if (targetServerSock == INVALID_SOCKET)
	{
		log("%s %d error\r\n", __FUNCTION__, __LINE__);
		MessageBoxA(0, "TargetServer informerUdpListener error", "TargetServer informerUdpListener error", MB_OK);
		ExitProcess(0);
		return -1;
	}

	char szbuf[1024];

	CONNECTION_INFO connectinfo = { 0 };
	while (TRUE)
	{
		int iClientSockSize = sizeof(sockaddr_in);

		connectinfo.udptarget = instance->mUdp;
		connectinfo.ssltarget = instance->mClients;

		int recvlen = recvfrom(targetServerSock, szbuf, sizeof(szbuf), 0,(sockaddr*)&connectinfo.sa, &iClientSockSize);

		if (recvlen > 0)
		{
			*(szbuf + recvlen) = 0;

			unsigned long inetip = connectinfo.sa.sin_addr.S_un.S_addr;

			string ip = HttpUtils::getIPstr(inetip);

			string username = string(szbuf);

			ret = connectinfo.ssltarget->storeTarget(ip, username);
		}
		else
		{
			log("%s %d error\r\n", __FUNCTION__, __LINE__);
			continue;
		}
	}

}