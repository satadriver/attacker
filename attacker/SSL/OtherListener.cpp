#include "OtherListener.h"
#include <windows.h>
#include "sslPublic.h"
#include "HttpProxy.h"
#include "HttpProxyListener.h"
#include "../HttpUtils.h"
#include "../Deamon.h"
#include "../Public.h"
#include "../utils/BaseSocket.h"
#include "../utils/Tools.h"
#include "HttpProxyListener.h"





OtherListener::OtherListener(int port) {
	if (mInstance)
	{
		return;
	}
	mInstance = this;
	mPort = port;

	CloseHandle(CreateThread(0, 0, (LPTHREAD_START_ROUTINE)listener, this, 0, 0));
}

OtherListener::~OtherListener() {

}

int	__stdcall OtherListener::listener(OtherListener * instance){
	int ret = 0;
	char szout[1024];

	instance->mSock = BaseSocket::listenPort(instance->mPort);
	if ((instance->mSock == SOCKET_ERROR) || (instance->mSock == INVALID_SOCKET))
	{
		printf("HTTP listenPort error\r\n");
		Public::WriteLogFile("HTTP listenPort error\r\n");
		MessageBoxA(0, "HTTPProxyListener listenPort error", "HTTPProxyListener listenPort error", MB_OK);
		exit(-1);
	}
	else
	{
		printf("HTTP listener is ready\r\n");
	}

	while (TRUE)
	{
		__try
		{
			int iClientSockSize = sizeof(sockaddr_in);
			sockaddr_in saClient = { 0 };
			int sockClient = accept(instance->mSock, (sockaddr*)&saClient, &iClientSockSize);
			if (sockClient != INVALID_SOCKET && sockClient > 0)
			{
				LPHTTPPROXYPARAM pstHttpProxyParam = (LPHTTPPROXYPARAM)new HTTPPROXYPARAM;
				memset(pstHttpProxyParam, 0, sizeof(HTTPPROXYPARAM));
				pstHttpProxyParam->usPort = instance->mPort;
				pstHttpProxyParam->timeclient = time(0);
				pstHttpProxyParam->timeserver = pstHttpProxyParam->timeclient;
				pstHttpProxyParam->sockToClient = sockClient;
				pstHttpProxyParam->saToClient = saClient;

				Deamon::addHttp(pstHttpProxyParam);

				int overtime = CONNECTION_TIME_OUT;
				ret = setsockopt(pstHttpProxyParam->sockToClient, SOL_SOCKET, SO_RCVTIMEO, (char *)&overtime, sizeof(int));
				ret += setsockopt(pstHttpProxyParam->sockToClient, SOL_SOCKET, SO_SNDTIMEO, (char *)&overtime, sizeof(int));

				ret = HttpProxy::HttpProxyMain(pstHttpProxyParam);

				Deamon::removeHttp(pstHttpProxyParam);
			}
			else
			{
				wsprintfA(szout, "HTTP监听线程accept错误码:%d\n", WSAGetLastError());
				Public::WriteLogFile(szout);
				printf(szout);

				closesocket(instance->mSock);

				instance->mSock = BaseSocket::listenPort(instance->mPort);
				if ((instance->mSock == SOCKET_ERROR) || (instance->mSock == INVALID_SOCKET))
				{
					printf("OtherListener listenPort error\r\n");
					Public::WriteLogFile("OtherListener listenPort error\r\n");
					exit(-1);
					return FALSE;
				}
			}
		}
		__except (1)
		{
			SYSTEMTIME stSysTm = { 0 };
			GetLocalTime(&stSysTm);
			int len = wsprintfA(szout, "OtherListener监听线程发生异常,错误码:%u,时间:%d.%d.%d %d:%d:%d\r\n", GetLastError(),
				stSysTm.wYear, stSysTm.wMonth, stSysTm.wDay, stSysTm.wHour, stSysTm.wMinute, stSysTm.wSecond);
			printf(szout);
			Public::WriteLogFile(ATTACK_LOG_FILENAME, szout, len);
			return FALSE;
		}
		
	}

}



