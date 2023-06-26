
#include <windows.h>
#include <vector>
#include "SSLRetransfer.h"
#include "sslPublic.h"
#include "../HttpUtils.h"
#include "../Deamon.h"
#include <mstcpip.h>
#include "HttpProxy.h"
#include "AttackSplitPacket.h"



int SSLRetransfer::RetransferProxyMain(LPHTTPPROXYPARAM pstHttpProxyParam) {
	int				iCounter = 0;
	int				iRet = 0;
	unsigned char	recvBuffer[NETWORK_BUFFER_SIZE + 4] ;
	char szout[1024];

	iCounter = recv(pstHttpProxyParam->sockToClient, (char*)recvBuffer, NETWORK_BUFFER_SIZE, 0);
	if (iCounter <= 0)
	{
		return FALSE;
	}
	*(recvBuffer + iCounter) = 0;

	string host = pstHttpProxyParam->host;
	if (host == "")
	{
		char * httpdata = 0;
		string httphdr = "";
		string url = "";
		string host = "";
		int port = 0;
		int type = 0;
		iRet = HttpUtils::parseHttpHdr((char*)recvBuffer, iCounter, type, httphdr, &httpdata, url, host, port);
		if (iRet < 0)
		{
			return FALSE;
		}
		else if (iRet == 0)
		{
			iRet = AttackSplitPacket::splitPacket((char*)recvBuffer, iCounter, pstHttpProxyParam, httphdr, &httpdata, url, host, port);
			if (iRet <= 0)
			{
				Public::WriteLogFile(ATTACK_LOG_FILENAME, (unsigned char *)recvBuffer, iCounter, "\r\nhttp splitPacket error:\r\n");
				return FALSE;
			}
		}

		lstrcpyA(pstHttpProxyParam->host, host.c_str());
	}

	if (*pstHttpProxyParam->host == 0)
	{
		return TRUE;
	}

	if (strstr(pstHttpProxyParam->host, "127.0.0.1") || pstHttpProxyParam->saToClient.sin_addr.S_un.S_addr == 0x0100007f ||
		(pstHttpProxyParam->saToClient.sin_addr.S_un.S_addr == gLocalIPAddr && gAttackMode != 3) )
	{
		return FALSE;
	}

	if (strstr(pstHttpProxyParam->host, gstrServerIP.c_str()) || 
		strstr(pstHttpProxyParam->host, gstrLocalIP.c_str()) ||
		strstr(pstHttpProxyParam->host, MYOWNSITE_ATTACK_DOMAINNAME) )
	{
		return FALSE;
	}


	DWORD dwip = HttpUtils::getIPFromHost(host);
	if (dwip == 0 || *pstHttpProxyParam->host == 0)
	{
		int outlen = wsprintfA(szout, "\r\nRetransferProxyMain getIPFromHost:%s error\r\n", host.c_str());
		Public::WriteLogFile(ATTACK_LOG_FILENAME, (unsigned char *)recvBuffer, iCounter, szout);
		printf(szout);
		return FALSE;
	}



	pstHttpProxyParam->sockToServer = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (pstHttpProxyParam->sockToServer == INVALID_SOCKET)
	{
		printf("RetransferProxyMain server:%s socket error:%d\r\n", host.c_str(), WSAGetLastError());
		return FALSE;
	}
	pstHttpProxyParam->saToServer.sin_addr.S_un.S_addr = dwip;
	pstHttpProxyParam->saToServer.sin_family = AF_INET;
	pstHttpProxyParam->saToServer.sin_port = htons(pstHttpProxyParam->usPort);

	int overtime = CONNECTION_TIME_OUT;
	iRet = setsockopt(pstHttpProxyParam->sockToServer, SOL_SOCKET, SO_RCVTIMEO, (char *)&overtime, sizeof(int));
	iRet += setsockopt(pstHttpProxyParam->sockToServer, SOL_SOCKET, SO_SNDTIMEO, (char *)&overtime, sizeof(int));
	
	iRet = connect(pstHttpProxyParam->sockToServer, (sockaddr*)&(pstHttpProxyParam->saToServer), sizeof(sockaddr_in));
	if (iRet == SOCKET_ERROR)
	{
		printf("RetransferProxyMain connect server:%s error:%d\r\n", host.c_str(), WSAGetLastError());
		return FALSE;
	}

	iRet = send(pstHttpProxyParam->sockToServer, (char*)recvBuffer, iCounter, 0);
	if (iRet != iCounter)
	{
		printf("RetransferProxyMain send server:%s error:%d\r\n",host.c_str(), WSAGetLastError());
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
		else if (iRet == 0)
		{
			break;
		}

		if (FD_ISSET(pstHttpProxyParam->sockToClient, &stFdSet))
		{
			iCounter = recv(pstHttpProxyParam->sockToClient, (char*)recvBuffer, NETWORK_BUFFER_SIZE, 0);
			if (iCounter <= 0)
			{
				break;
			}

			*(recvBuffer + iCounter) = 0;

			iRet = send(pstHttpProxyParam->sockToServer, (char*)recvBuffer, iCounter, 0);
			if (iRet != iCounter)
			{
				break;
			}
			pstHttpProxyParam->timeclient = time(0);
		}

		if (FD_ISSET(pstHttpProxyParam->sockToServer, &stFdSet))
		{
			iCounter = recv(pstHttpProxyParam->sockToServer, (char*)recvBuffer, NETWORK_BUFFER_SIZE, 0);
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