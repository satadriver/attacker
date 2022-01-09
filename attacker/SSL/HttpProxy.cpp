
#include <windows.h>
#include "sslPublic.h"
#include "../HttpUtils.h"
#include "HttpProxy.h"
#include "PluginServer.h"
#include "HttpAttack.h"
#include "../Public.h"
#include "../Deamon.h"
#include <mstcpip.h>
#include <vector>


int HttpProxy::HttpProxyMain(LPHTTPPROXYPARAM pstHttpProxyParam) {
	int				iCounter = 0;
	int				iRet = 0;
	unsigned char	recvBuffer[NETWORK_BUFFER_SIZE + 4];
	char szout[1024];

	iCounter = recv(pstHttpProxyParam->sockToClient, (char*)recvBuffer, NETWORK_BUFFER_SIZE, 0);
	if (iCounter <= 0)
	{
		return FALSE;
	}
	*(recvBuffer + iCounter) = 0;

	iRet = HttpAttack::httpAttackProc((char*)recvBuffer, iCounter, pstHttpProxyParam);
	if (iRet > 0 )
	{
		return FALSE;
	}

	DWORD dwip = HttpUtils::getIPFromHost(pstHttpProxyParam->host);
	if (dwip == 0) {
#ifdef _DEBUG
		iRet = wsprintfA(szout,"HTTP getIPFromHost:%s error\r\n", pstHttpProxyParam->host);
		Public::WriteLogFile(ATTACK_LOG_FILENAME, (unsigned char *)recvBuffer, iCounter, szout);
		printf(szout);
#endif
		return FALSE;
	}
	else {
		pstHttpProxyParam->sockToServer = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (pstHttpProxyParam->sockToServer <= 0)
		{
			printf("HTTP %s socket server error:%d\r\n", pstHttpProxyParam->host,WSAGetLastError());
			return FALSE;
		}
		int overtime = CONNECTION_TIME_OUT;
		iRet = setsockopt(pstHttpProxyParam->sockToServer, SOL_SOCKET, SO_RCVTIMEO, (char *)&overtime, sizeof(int));
		iRet += setsockopt(pstHttpProxyParam->sockToServer, SOL_SOCKET, SO_SNDTIMEO, (char *)&overtime, sizeof(int));

		pstHttpProxyParam->saToServer.sin_addr.S_un.S_addr = dwip;
		pstHttpProxyParam->saToServer.sin_port = ntohs(pstHttpProxyParam->usPort);
		pstHttpProxyParam->saToServer.sin_family = AF_INET;
	}

	iRet = connect(pstHttpProxyParam->sockToServer, (sockaddr*)&(pstHttpProxyParam->saToServer), sizeof(sockaddr_in));
	if (iRet )
	{
		printf("HTTP connect server:%s,ip:%08x error:%u\r\n",pstHttpProxyParam->host,
			pstHttpProxyParam->saToServer.sin_addr.S_un.S_addr, WSAGetLastError());
		return FALSE;
	}

	iRet = send(pstHttpProxyParam->sockToServer, (char*)recvBuffer, iCounter, 0);
	if (iRet != iCounter )
	{
		printf("HTTP %s send server error:%d\r\n",pstHttpProxyParam->host,WSAGetLastError());
		return FALSE;
	}

	fd_set			stFdSet = { 0 };
	timeval			stTmVal = { 0 };
	stTmVal.tv_sec = SELECT_TIME_OUT / 1000;
	stTmVal.tv_usec = 0;

	SOCKET selectsock = pstHttpProxyParam->sockToServer;
	if (pstHttpProxyParam->sockToClient > pstHttpProxyParam->sockToServer)
	{
		selectsock = pstHttpProxyParam->sockToClient;
	}

#undef FD_SETSIZE
#define FD_SETSIZE 1024

	while (TRUE)
	{
		FD_ZERO(&stFdSet);
		FD_SET(pstHttpProxyParam->sockToClient, &stFdSet);
		FD_SET(pstHttpProxyParam->sockToServer, &stFdSet);

		iRet = select(selectsock + 1, &stFdSet, NULL, NULL, &stTmVal);
		if (iRet <= 0 || iRet > 2)
		{
			break;
		}

		if (FD_ISSET(pstHttpProxyParam->sockToClient, &stFdSet))
		{
			iCounter = recv(pstHttpProxyParam->sockToClient,(char*)recvBuffer, NETWORK_BUFFER_SIZE,0);
			if (iCounter <= 0)
			{
				break;
			}

			*(recvBuffer + iCounter) = 0;

			iRet = HttpAttack::httpAttackProc((char*)recvBuffer, iCounter, pstHttpProxyParam);
			if (iRet > 0)
			{
				break;
			}

			iRet = send(pstHttpProxyParam->sockToServer, (char*)recvBuffer, iCounter, 0);
			if (iRet != iCounter)
			{
				break;
			}

			pstHttpProxyParam->timeclient = time(0);
		}

		if (FD_ISSET(pstHttpProxyParam->sockToServer, &stFdSet))
		{
			iCounter = recv(pstHttpProxyParam->sockToServer,(char*)recvBuffer, NETWORK_BUFFER_SIZE,0);
			if (iCounter <= 0)
			{
				break;
			}

			*(recvBuffer + iCounter) = 0;

			iRet = send(pstHttpProxyParam->sockToClient, (char*)recvBuffer, iCounter, 0);
			if (iRet != iCounter)
			{
				break;
			}

			pstHttpProxyParam->timeserver = time(0);
		}
	}
	
	return TRUE;
}

//无线网的MAC值的第二个数只能是2 、6、A、E中的一个，否则修改就不会起作用，如060C29E7B28C。
//MAC地址是由48位Bit组成（第一个字节最低位一定是0），在通信中使用16进制，即6个字节。
//虽然mac地址可以修改，但是不要乱改，至少需要能保证在使用的局域网内是唯一。

int __stdcall HttpProxy::HTTPProxy(LPWORKCONTROL param)
{
	LPHTTPPROXYPARAM pstHttpProxyParam = 0;
	char szout[1024];
	int ret = 0;
	while (TRUE)
	{
		__try
		{
			ret = WaitForSingleObject(param->gHTTPEvent, INFINITE);

			pstHttpProxyParam = param->gHTTPProxyParam;

			ret = SetEvent(param->gHTTPListenEvent);

			int overtime = CONNECTION_TIME_OUT;

			ret = setsockopt(pstHttpProxyParam->sockToClient, SOL_SOCKET, SO_RCVTIMEO, (char *)&overtime, sizeof(int));

			ret += setsockopt(pstHttpProxyParam->sockToClient, SOL_SOCKET, SO_SNDTIMEO, (char *)&overtime, sizeof(int));

			ret = HttpProxyMain(pstHttpProxyParam);

			Deamon::removeHttp(pstHttpProxyParam);
		}
		__except (1)
		{
			SYSTEMTIME stSysTm = { 0 };
			GetLocalTime(&stSysTm);
			int len = wsprintfA(szout, "HTTP客户端代理线程发生异常,错误码:%u,线程ID:%u,时间:%d.%d.%d %d:%d:%d\r\n", GetLastError(),
				pstHttpProxyParam->ulThreadID, stSysTm.wYear, stSysTm.wMonth, stSysTm.wDay, stSysTm.wHour, stSysTm.wMinute, stSysTm.wSecond);
			printf( szout);
			Public::WriteLogFile(ATTACK_LOG_FILENAME, szout, len);
		}
	}

	return TRUE;
}