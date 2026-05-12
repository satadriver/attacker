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
#include "../Utils/Tools.h"




OtherListener::OtherListener(int port) {

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
		char szstr[1024];
		wsprintfA(szstr, "%s %d error\r\n",__FUNCTION__,__LINE__);
		log(szstr);
		MessageBoxA(0, szstr, szstr, MB_OK);
		exit(-1);
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
				LPHTTPPROXYPARAM hpp = (LPHTTPPROXYPARAM)new HTTPPROXYPARAM;
				memset(hpp, 0, sizeof(HTTPPROXYPARAM));
				hpp->usPort = instance->mPort;
				hpp->timeclient = time(0);
				hpp->timeserver = hpp->timeclient;
				hpp->sockToClient = sockClient;
				hpp->saToClient = saClient;

				Deamon::addHttp(hpp);

				int overtime = CONNECTION_TIME_OUT;
				ret = setsockopt(hpp->sockToClient, SOL_SOCKET, SO_RCVTIMEO, (char *)&overtime, sizeof(int));
				ret += setsockopt(hpp->sockToClient, SOL_SOCKET, SO_SNDTIMEO, (char *)&overtime, sizeof(int));

				ret = HttpProxy::HttpProxyMain(hpp);

				Deamon::removeHttp(hpp);
			}
			else
			{
				log( "%s %d error\r\n", __FUNCTION__, __LINE__);

				closesocket(instance->mSock);

				instance->mSock = BaseSocket::listenPort(instance->mPort);
				if ((instance->mSock == SOCKET_ERROR) || (instance->mSock == INVALID_SOCKET))
				{
					log("%s %d error\r\n", __FUNCTION__, __LINE__);
					exit(-1);
					return FALSE;
				}
			}
		}
		__except (1)
		{
			log("%s %d error\r\n", __FUNCTION__, __LINE__);
		}
		
	}

}



