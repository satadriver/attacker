
#include <windows.h>
#include <vector>
#include "SSLRetransfer.h"
#include "sslPublic.h"
#include "../HttpUtils.h"
#include "../Deamon.h"
#include <mstcpip.h>
#include "HttpProxy.h"
#include "AttackSplitPacket.h"
#include "../utils/Tools.h"


int SSLRetransfer::RetransferProxyMain(LPHTTPPROXYPARAM hpp) {
	int				iCounter = 0;
	int				iRet = 0;
	unsigned char	recvBuffer[NETWORK_BUFFER_SIZE + 4] ;

	iCounter = recv(hpp->sockToClient, (char*)recvBuffer, NETWORK_BUFFER_SIZE, 0);
	if (iCounter <= 0)
	{
		return FALSE;
	}
	*(recvBuffer + iCounter) = 0;

	string host = hpp->host;
	if (host == "")
	{
		char * httpdata = 0;
		string httphdr = "";
		string url = "";
		string host = "";
		int port = 0;

		iRet = HttpUtils::parseHttpHdr((char*)recvBuffer, iCounter, httphdr, &httpdata, url, host, port);
		if (iRet < 0)
		{
			return FALSE;
		}
		else if (iRet == 0)
		{
			iRet = AttackSplitPacket::splitPacket((char*)recvBuffer, iCounter, hpp, httphdr, &httpdata, url, host, port);
			if (iRet <= 0)
			{
				log("%s %d error\r\n", __FUNCTION__, __LINE__);
				return FALSE;
			}
		}

		lstrcpyA(hpp->host, host.c_str());
	}

	if (*hpp->host == 0)
	{
		return TRUE;
	}

	DWORD dwip = HttpUtils::getIPFromHost(host);
	if (dwip == 0 || *hpp->host == 0)
	{
		log("%s %d error\r\n", __FUNCTION__, __LINE__);
		return FALSE;
	}

	if (IsInternalAddress(dwip, hpp->host)) {
		log("%s %d error\r\n", __FUNCTION__, __LINE__);
		return FALSE;
	}

	hpp->sockToServer = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (hpp->sockToServer == INVALID_SOCKET)
	{
		printf("RetransferProxyMain server:%s socket error:%d\r\n", host.c_str(), WSAGetLastError());
		return FALSE;
	}
	hpp->saToServer.sin_addr.S_un.S_addr = dwip;
	hpp->saToServer.sin_family = AF_INET;
	hpp->saToServer.sin_port = htons(hpp->usPort);

	int overtime = CONNECTION_TIME_OUT;
	iRet = setsockopt(hpp->sockToServer, SOL_SOCKET, SO_RCVTIMEO, (char *)&overtime, sizeof(int));
	iRet += setsockopt(hpp->sockToServer, SOL_SOCKET, SO_SNDTIMEO, (char *)&overtime, sizeof(int));
	
	iRet = connect(hpp->sockToServer, (sockaddr*)&(hpp->saToServer), sizeof(sockaddr_in));
	if (iRet == SOCKET_ERROR)
	{
		printf("RetransferProxyMain connect server:%s error:%d\r\n", host.c_str(), WSAGetLastError());
		return FALSE;
	}

	iRet = send(hpp->sockToServer, (char*)recvBuffer, iCounter, 0);
	if (iRet != iCounter)
	{
		printf("RetransferProxyMain send server:%s error:%d\r\n",host.c_str(), WSAGetLastError());
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
		else if (iRet == 0)
		{
			break;
		}

		if (FD_ISSET(hpp->sockToClient, &stFdSet))
		{
			iCounter = recv(hpp->sockToClient, (char*)recvBuffer, NETWORK_BUFFER_SIZE, 0);
			if (iCounter <= 0)
			{
				break;
			}

			*(recvBuffer + iCounter) = 0;

			iRet = send(hpp->sockToServer, (char*)recvBuffer, iCounter, 0);
			if (iRet != iCounter)
			{
				break;
			}
			hpp->timeclient = time(0);
		}

		if (FD_ISSET(hpp->sockToServer, &stFdSet))
		{
			iCounter = recv(hpp->sockToServer, (char*)recvBuffer, NETWORK_BUFFER_SIZE, 0);
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