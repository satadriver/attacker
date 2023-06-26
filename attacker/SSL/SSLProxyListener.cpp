

#include <windows.h>
#include <WINSOCK2.H>

#include "sslPublic.h"
#include "sslPacket.h"
#include "SSLProxy.h"
#include "sslproxylistener.h"
#include "../utils/BaseSocket.h"
#include "../attacker.h"
#include "../Deamon.h"
#include "../HttpUtils.h"
#include "..\\include\\openssl\\ssl.h"
#include "..\\include\\openssl\\err.h"
#include "../utils/Tools.h"
#include "sslEntry.h"

//vmvare-hosted.exe 占用443端口

SslProxyListener::SslProxyListener() {
	if (mInstance)
	{
		return;
	}
	mInstance = this;

	SslProxy *sslproxy = new SslProxy();

	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	SSLPublic::freeSSLPort();

	mSock = BaseSocket::listenPort(SSL_PORT);
	if ((mSock == SOCKET_ERROR) || (mSock == INVALID_SOCKET))
	{
		printf("SSL listenPort error\r\n");
		Public::WriteLogFile("SSL listenPort error\r\n");
		MessageBoxA(0, "ssl init error", "ssl init error", MB_OK);
		exit(-1);
	}
	else
	{
		printf("SSL listener is ready\n");
	}

	gWorkControl.gSSLEvent = CreateEventA(0, 0, 0, "gSSLEvent");

	gWorkControl.gSSLListenEvent = CreateEventA(0, 0, TRUE, "gSSLListenEvent");

	CloseHandle(CreateThread(0, PROXY_THREAD_STACK_SIZE, (LPTHREAD_START_ROUTINE)SslProxyListener::listener, this,
		STACK_SIZE_PARAM_IS_A_RESERVATION, 0));

	int cnt = SSL_WORK_THREAD_CNT;
	for (int i = 0; i < cnt; i++)
	{
		CloseHandle(CreateThread(0, 0, (LPTHREAD_START_ROUTINE)SslProxy::SSLConnection, &gWorkControl, 0, 0));
	}
}


SslProxyListener::~SslProxyListener() {
	closesocket(mSock);
}

int __stdcall SslProxyListener::listener(SslProxyListener*instance)
{
	char szout[1024];
	int ret = 0;
	while (TRUE)
	{
		__try
		{
			ret = WaitForSingleObject(gWorkControl.gSSLListenEvent, INFINITE);

			sockaddr_in saclient = { 0 };
			int iClientSockSize = sizeof(sockaddr_in);
			int sockclient = accept(instance->mSock, (sockaddr*)&saclient, &iClientSockSize);
			if ((sockclient != INVALID_SOCKET) && (sockclient > 0))
			{
				LPSSLPROXYPARAM pstSSLProxyParam = (LPSSLPROXYPARAM)new SSLPROXYPARAM;
				memset(pstSSLProxyParam, 0, sizeof(SSLPROXYPARAM));
				pstSSLProxyParam->usPort = SSL_PORT;
				pstSSLProxyParam->saToClient = saclient;
				pstSSLProxyParam->sockToClient = sockclient;
				pstSSLProxyParam->timeclient = time(0);
				pstSSLProxyParam->timeserver = pstSSLProxyParam->timeclient;

				Deamon::addSSL(pstSSLProxyParam);

				gWorkControl.gSSLProxyParam = pstSSLProxyParam;

				ret = SetEvent(gWorkControl.gSSLEvent);
			}
			else
			{
				wsprintfA(szout, "SSL监听线程accept错误码:%d\n", WSAGetLastError());
				Public::WriteLogFile(szout);
				printf(szout);

				closesocket(instance->mSock);

				instance->mSock = BaseSocket::listenPort(SSL_PORT);
				if ((instance->mSock == SOCKET_ERROR) || (instance->mSock == INVALID_SOCKET))
				{
					printf("SSL listenPort error\r\n");
					Public::WriteLogFile("SSL listenPort error\r\n");
					exit(-1);
				}

				SetEvent(gWorkControl.gSSLListenEvent);
			}
		}
		__except (1)
		{
			SYSTEMTIME stSysTm = { 0 };
			GetLocalTime(&stSysTm);
			int len = wsprintfA(szout, "SSL监听线程发生异常,错误码:%u,时间:%d.%d.%d %d:%d:%d\r\n", WSAGetLastError(),
				stSysTm.wYear, stSysTm.wMonth, stSysTm.wDay, stSysTm.wHour, stSysTm.wMinute, stSysTm.wSecond);

			Public::WriteLogFile(ATTACK_LOG_FILENAME, szout, len);
			printf(szout);
		}
	}
	return TRUE;
}

