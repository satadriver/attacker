#include "../ssl/sslPublic.h"
#include "DnsProxy.h"
#include <stdio.h>
#include "../HttpUtils.h"
#include "../Packet.h"
#include "../ssl/InformerClient.h"
#include <vector>
#include "dnsUtils.h"
#include "../Utils/BaseSocket.h"

#include <string>

using namespace std;



DnsProxy::DnsProxy(unsigned long serverip) {
	if (mInstance)
	{
		return;
	}

	mInstance = this;

	mServerip = serverip;

	gDnsResultMap.clear();

	createQuerySock(DNS_QUERY_TIMEOUT);

	DWORD dnsThreadid = 0;
	CloseHandle(CreateThread(0, PROXY_THREAD_STACK_SIZE, (LPTHREAD_START_ROUTINE)DnsProxy::DnsProxyListener,
		(LPVOID)mInstance, STACK_SIZE_PARAM_IS_A_RESERVATION, &dnsThreadid));
}


DnsProxy::~DnsProxy() {

}



int __stdcall DnsProxy::DnsProxyListener(DnsProxy * instance){

	DNSANSWER			stDnsAnswer = { 0 };
	stDnsAnswer.Name = htons(0xc00c);
	stDnsAnswer.Type = htons(0x0001);
	stDnsAnswer.Class = htons(0x0001);
	stDnsAnswer.HighTTL = htons(0x0000);
	stDnsAnswer.LowTTL = htons(0x0080);
	stDnsAnswer.AddrLen = htons(0x0004);
	stDnsAnswer.Address = instance->mServerip;

	DNSANSWERIPV6 stDnsAnswerIPV6 = { 0 };
	stDnsAnswerIPV6.Name = htons(0xc00c);
	stDnsAnswerIPV6.Type = htons(0x001c);
	stDnsAnswerIPV6.Class = htons(0x0001);
	stDnsAnswerIPV6.HighTTL = htons(0x0000);
	stDnsAnswerIPV6.LowTTL = htons(0x0040);
	stDnsAnswerIPV6.AddrLen = htons(0x0010);
	HttpUtils::ipv4toipv6((unsigned char*)&instance->mServerip, stDnsAnswerIPV6.Address);

	char szout[2048];

	int iRet = 0;
	instance->mSockDns = BaseSocket::listenUdpPort(DNS_PORT);
	if (instance->mSockDns <= 0)
	{
		Public::WriteLogFile("DnsProxyListener socket error\r\n");
		printf("DnsProxyListener socket error\n");
		exit(-1);
	}
	//linux
// 	struct timeval TimeOut = { 0 };
// 	TimeOut.tv_sec = 60;
// 	TimeOut.tv_usec = 0;
// 	iRet += ::setsockopt(instance->mSockDns, SOL_SOCKET, SO_RCVTIMEO, (char *)&TimeOut, sizeof(TimeOut));
// 	iRet += ::setsockopt(instance->mSockDns, SOL_SOCKET, SO_SNDTIMEO, (char *)&TimeOut, sizeof(TimeOut));

	//windows
// 	int timeout = 360000;
// 	iRet = ::setsockopt(instance->mSockDns, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
// 	//iRet += ::setsockopt(instance->mSockDns, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));
// 	if (iRet) {
// 		printf("DnsProxyListener setsockopt error\n");
// 		Public::WriteLogFile("DnsProxyListener setsockopt error\r\n");
// 	}

	int counter = 0;
	char lpdns[DNS_PACKET_LIMIT +1024];

	while (TRUE)
	{
		__try {
			struct sockaddr_in saclient = { 0 };
			int clientaddrlen = sizeof(sockaddr_in);
			int dnslen = recvfrom(instance->mSockDns, lpdns, DNS_PACKET_LIMIT, 0, (sockaddr*)&saclient, &clientaddrlen);
			if (dnslen > DNS_PACKET_LIMIT || dnslen <= 0)
			{
				int len = wsprintfA(szout, "DnsProxyListener recv length:%d error:%d\r\n", dnslen,WSAGetLastError());
				Public::WriteLogFile(DNS_LOG_FILENAME, szout, len);
				printf(szout);
				continue;
			}

			*(lpdns + dnslen) = 0;

			LPDNSTYPECLASS dnstc = (LPDNSTYPECLASS)(lpdns + dnslen - sizeof(DNSTYPECLASS));

			char * lpqueryname = lpdns + sizeof(DNSHEADER);
			iRet = DnsUitls::isTargetDNS(lpqueryname);
			if (iRet)
			{
				LPDNSHEADER pDnsHdr = (LPDNSHEADER)(lpdns);
				pDnsHdr->Flags = 0x8081;
				pDnsHdr->Questions = 0x0100;
				pDnsHdr->AnswerRRS = 0x0100;
				pDnsHdr->AuthorityRRS = 0x0000;
				pDnsHdr->AdditionalRRS = 0x0000;

				int addsize = 0;
				if (dnstc->dnstype == 0x1c00)
				{
					memcpy((char*)lpdns + dnslen, (char *)&stDnsAnswerIPV6, sizeof(DNSANSWERIPV6));
					addsize = sizeof(DNSANSWERIPV6);
				}else if (dnstc->dnstype == 0x0100)
				{
					memcpy((char*)lpdns + dnslen, (char *)&stDnsAnswer, sizeof(DNSANSWER));
					addsize = sizeof(DNSANSWER);
				}
				else {
					continue;
				}

				int sendlen = sendto(instance->mSockDns, lpdns, addsize + dnslen, 0, (sockaddr*)&saclient, clientaddrlen);
				if (sendlen != addsize + dnslen) {
					int len = wsprintfA(szout, "DnsProxyListener reply IP:%s,port:%d,dns:%s error\r\n",
						inet_ntoa(saclient.sin_addr), ntohs(saclient.sin_port), lpdns + addsize);
					Public::WriteLogFile(DNS_LOG_FILENAME, szout, len);
					printf(szout);
				}
				else {
// 					int len = wsprintfA(szout, "DnsProxyListener reply IP:%s,port:%d,dns:%s ok\r\n",
// 						inet_ntoa(saclient.sin_addr), ntohs(saclient.sin_port), lpdns + addsize);
// 					Public::WriteLogFile(DNS_LOG_FILENAME, szout, len);
// 					printf(szout);
					
					counter++;

					//string strhost = DnsUitls::dns2Host(lpqueryname);
					//InformerClient::storeTarget(strhost, G_USERNAME);
				}
			}
			else {
				int sendlen = 0;

				char *dnsresult = 0;

				string dnskey = lpqueryname;
				if (dnstc->dnstype == 0x1c00)
				{
					dnskey = dnskey + "_ipv6";
				}else if (dnstc->dnstype == 0x0100)
				{
					dnskey = dnskey + "_ipv4";
				}
				else {
					continue;
				}

				unordered_map <string, char *>::iterator it = instance->gDnsResultMap.find(dnskey);
				if (it == instance->gDnsResultMap.end())
				{
					char * lpdata = new char[DNS_PACKET_LIMIT*2];
					dnsresult = lpdata + sizeof(int);
					sendlen = getIPFromDNS(lpdns, dnslen, dnsresult,instance);
					if (sendlen > 0) {
						*(int*)lpdata = sendlen;
						pair< std::unordered_map<string, char *>::iterator, bool > itret;
						itret = instance->gDnsResultMap.insert(pair<string, char *>(dnskey, lpdata));
						if (itret.second == 0)
						{
							delete[]lpdata;

							int len = wsprintfA(szout, "DnsProxyListener insert dns:%s error:%u\r\n", dnskey, GetLastError());
							Public::WriteLogFile(DNS_LOG_FILENAME, szout, len);
						}
					}
					else {
						delete[]lpdata;

						int len = wsprintfA(szout, "DnsProxyListener get dns:%s error\r\n", dnskey);
						Public::WriteLogFile(DNS_LOG_FILENAME, szout, len);
						printf(szout);
						continue;
					}
				}
				else {
					sendlen = *(int*)(it->second);
					dnsresult = it->second + sizeof(int);
				}

				WORD dnsid = *(WORD*)lpdns;
				*(WORD*)dnsresult = dnsid;
				iRet = sendto(instance->mSockDns, dnsresult, sendlen, 0, (sockaddr*)&saclient, clientaddrlen);
				if (iRet <= 0)
				{
					int len = wsprintfA(szout, "DnsProxyListener send answer dns:%s error\r\n", dnskey);
					Public::WriteLogFile(DNS_LOG_FILENAME, szout, len);
					printf(szout);
				}
			}
		}
		__except (1) {
			Public::WriteLogFile("DnsProxyListener exception\r\n");
		}
	}
	
	closesocket(instance->mSockDns);
	return 0;
}






int DnsProxy::createQuerySock(int timeout) {
	int ret = 0;
	mSockQuery = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (mSockQuery <= 0)
	{
		mSockQuery = 0;
		return FALSE;
	}

	ret = ::setsockopt(mSockQuery, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
	//ret += ::setsockopt(mSockQuery, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));
	return mSockQuery;
}



unsigned int DnsProxy::getIPFromDNS(const char * dnsbuf, int sendlen, char * data,DnsProxy * instance) {
	int ret = 0;
	int recvsize = 0;
	char szout[1024];

	__try
	{
		if (instance->mSockQuery <= 0)
		{
			instance->mSockQuery = instance->createQuerySock(DNS_QUERY_TIMEOUT);
			if (instance->mSockQuery <= 0)
			{
				instance->mSockQuery = 0;
				Public::WriteLogFile("getIPFromDNS createDnsSock errror\r\n");
				return FALSE;
			}
		}

		sockaddr_in si = { 0 };
		si.sin_port = ntohs(DNS_PORT);
		si.sin_family = AF_INET;
		si.sin_addr.S_un.S_addr = LOCAL_DNS_QUERY_SERVER;

		int sendret = sendto(instance->mSockQuery, dnsbuf, sendlen, 0, (sockaddr*)&si, sizeof(sockaddr_in));
		if (sendret != sendlen)
		{
			closesocket(instance->mSockQuery);
			instance->mSockQuery = 0;
			Public::WriteLogFile("getIPFromDNS send error\r\n");
			return FALSE;
		}

		int sockaddrlen = sizeof(sockaddr_in);
		recvsize = recvfrom(instance->mSockQuery, data, DNS_PACKET_LIMIT, 0, (sockaddr*)&si, &sockaddrlen);
		if (recvsize <= 0)
		{
			closesocket(instance->mSockQuery);
			instance->mSockQuery = 0;
			Public::WriteLogFile("getIPFromDNS recv error\r\n");
			return FALSE;
		}
	}
	__except (1) {
		Public::WriteLogFile("getIPFromDNS excepiton\r\n");
		closesocket(instance->mSockQuery);
		instance->mSockQuery = 0;
		return FALSE;
	}
	return recvsize;
}




