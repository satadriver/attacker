

#include <windows.h>

#include "sslPublic.h"
#include "HttpProxy.h"
#include "HttpProxyListener.h"
#include "../HttpUtils.h"
#include "../Deamon.h"
#include "../Public.h"
#include "../utils/BaseSocket.h"
#include "../utils/Tools.h"

#include "sslEntry.h"

HttpProxyListener::HttpProxyListener() {

	mInstance = this;

	mSock = BaseSocket::listenPort(HTTP_PORT);
	if ((mSock == SOCKET_ERROR) || (mSock == INVALID_SOCKET))
	{
		char buf[1024];
		wsprintfA(buf,"[%s %d] listen:%d error\n", __FUNCTION__, __LINE__, HTTP_PORT);
		log(buf);
		MessageBoxA(0, buf, buf, MB_OK);
		exit(-1);
	}

	g_thread_params.gHTTPEvent = CreateEventA(0, 0, 0, "gHTTPEvent");

	g_thread_params.gHTTPListenEvent = CreateEventA(0, 0, TRUE, "gHTTPListenEvent");
	HANDLE ht = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)HttpProxyListener::listener,this, 0, 0);
	if(ht)
		CloseHandle(ht);

	int cnt = HTTP_WORK_THREAD_CNT;
	for (int i = 0; i < cnt; i++){
		ht = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)HttpProxy::HTTPProxy, &g_thread_params, 0, 0);
		if(ht)
			CloseHandle(ht);
	}
}



HttpProxyListener::~HttpProxyListener() {
	closesocket(mSock);
}

int __stdcall HttpProxyListener::listener(HttpProxyListener * instance)
{
	int ret = 0;
	char szout[1024];
	__try
	{
		while (TRUE)
		{
			ret = WaitForSingleObject(g_thread_params.gHTTPListenEvent, INFINITE);

			int css = sizeof(sockaddr_in);
			sockaddr_in saClient = { 0 };
			int sockClient = accept(instance->mSock, (sockaddr*)&saClient, &css);
			if (sockClient != INVALID_SOCKET && sockClient > 0)
			{
				LPHTTPPROXYPARAM hpp = (LPHTTPPROXYPARAM)new HTTPPROXYPARAM;
				memset(hpp, 0, sizeof(HTTPPROXYPARAM));
				hpp->usPort = HTTP_PORT;
				hpp->timeclient = time(0);
				hpp->timeserver = hpp->timeclient;
				hpp->sockToClient = sockClient;
				hpp->saToClient = saClient;

				Deamon::addHttp(hpp);

				g_thread_params.gHTTPProxyParam = hpp;

				ret = SetEvent(g_thread_params.gHTTPEvent);
			}
			else
			{
				log("%s %d error\r\n", __FUNCTION__, __LINE__);

				closesocket(instance->mSock);

				instance->mSock = BaseSocket::listenPort(HTTP_PORT);
				if ((instance->mSock == SOCKET_ERROR) || (instance->mSock == INVALID_SOCKET))
				{
					log("%s %d error\r\n", __FUNCTION__, __LINE__);
					exit(-1);
				}

				SetEvent(g_thread_params.gHTTPListenEvent);
			}
		}
	}
	__except (1)
	{
		log("%s %d exception\r\n", __FUNCTION__, __LINE__);
		return FALSE;
	}
}