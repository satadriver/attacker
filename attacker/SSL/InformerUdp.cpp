#include <conio.h>
#include "InformerUdp.h"
#include "informerproc.h"
#include "../utils/BaseSocket.h"
#include "../attacker.h"
#include "../informer.h"
#include "informerClient.h"
#include "sslPublic.h"
#include "../HttpUtils.h"
#include "../DnsUtils/dnsUtils.h"




InformerUDP::InformerUDP(InformerClient *client) {
	mClients = client;
	mUdp = this;
	CloseHandle(CreateThread(0, 0, (LPTHREAD_START_ROUTINE)informerUdpListener, this, 0, 0));
}


InformerUDP::~InformerUDP() {
	delete mClients;
}




int __stdcall InformerUDP::informerUdpListener(InformerUDP * instance) {
	int ret = 0;

	int targetServerSock = BaseSocket::listenUdpPort(INFORMER_PORT);
	if (targetServerSock == INVALID_SOCKET)
	{
		printf("targetServer informerUdpListener error\r\n");
		_getch();
		MessageBoxA(0, "TargetServer informerUdpListener error", "TargetServer informerUdpListener error", MB_OK);
		ExitProcess(0);
		return -1;
	}

	char szbuf[4096 + 16];

	CONNECTION_INFO connectinfo = { 0 };
	while (TRUE)
	{
		int iClientSockSize = sizeof(sockaddr_in);

		connectinfo.udptarget = instance->mUdp;
		connectinfo.ssltarget = instance->mClients;

		int recvlen = recvfrom(targetServerSock, szbuf, 4096, 0,(sockaddr*)&connectinfo.sa, &iClientSockSize);

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
			printf("targetServer recvfrom error:%d\r\n", WSAGetLastError());
			continue;
		}
	}

}