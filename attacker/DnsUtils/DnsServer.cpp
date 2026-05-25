

#include <windows.h>
#include "../Utils/Tools.h"
#include "../attacker.h"
#include "../ssl/sslPublic.h"
#include "DnsServer.h"
#include "../Packet.h"
#include "../utils/lock.h"
#include "../HttpUtils.h"


DnsServer*gDnsCenter = 0;

DnsServer::~DnsServer() {

}


DnsServer::DnsServer() {
	if (gDnsCenter)
	{
		return;
	}
	mInstance = this;
	gDnsCenter = this;

	gDnsCenterMap.clear();

	InitializeCriticalSection(&mCS);
}

unsigned long DnsServer::GetIPFromHost(string host){
	
	int ret = 0;

	unsigned long ip = 0;
	EnterCriticalSection(&gDnsCenter->mCS);
	DOMAININFO info;
	__try
	{
		unordered_map <string, DOMAININFO >::iterator it = gDnsCenter->gDnsCenterMap.find(host);
		if (it != gDnsCenter->gDnsCenterMap.end() )
		{
			DWORD cost = time(0) - it->second.dnstime;
			if (cost > 0 && cost < 24 * 3600) {
				ip = it->second.ip;
			}
		}

		if (ip == 0)
		{
			ip = DnsQuery(host, gDnsServer);
			if (ip == 0) {
				ip = DnsQuery(host, DNS_SERVER_ADDRESS );
				if (ip == 0) {
					ip = DnsQuery(host, BACK_DNS_SERVER_ADDRESS);
				}
			}
			if (ip)
			{		
				info.dnstime = time(0);
				info.ip = ip;
				if (it != gDnsCenter->gDnsCenterMap.end())
				{
					it->second.dnstime = info.dnstime;
					it->second.ip = ip;
				}
				else {
					pair< std::unordered_map<string, DOMAININFO>::iterator, bool > retit;
					retit = gDnsCenter->gDnsCenterMap.insert(pair<string, DOMAININFO>(host, info));
					if (retit.second == 0)
					{
						log("%s %d insert ip:%x,host:%s error:%u\r\n", __FUNCTION__, __LINE__, ip, host.c_str(), GetLastError());
					}
				}
			}
			else {
				//log( "getIPFromDomainName:%s error\r\n", host.c_str());
			}
		}
	}
	__except(1) 
	{
		log("%s %d host:%s exception\r\n", __FUNCTION__, __LINE__,host.c_str() );
	}

	LeaveCriticalSection(&gDnsCenter->mCS);
	
	return ip;
}




unsigned int DnsServer::DnsQuery(string host,DWORD dnsserver) {
	int ret = 0;

	char dnsbuf[DNS_PACKET_LIMIT+16] = { 0 };
	LPDNSHEADER dnshdr = (LPDNSHEADER)dnsbuf;
	dnshdr->TransactionID = LOCAL_QUERY_DNS_ID;
	dnshdr->Flags = 1;
	dnshdr->Questions = 0x100;
	dnshdr->AdditionalRRS = 0;
	dnshdr->AnswerRRS = 0;
	dnshdr->AuthorityRRS = 0;

	char * lpdnsname = dnsbuf + sizeof(DNSHEADER);
	string lphost = host;
	while (1)
	{
		int pos = lphost.find(".");
		if (pos > 0)
		{
			string sub = lphost.substr(0, pos);
			int sublen = sub.length();
			*lpdnsname = sublen;
			lpdnsname++;
			memcpy(lpdnsname, sub.c_str(), sublen);
			lpdnsname += sublen;
			lphost = lphost.substr(pos + 1);
		}
		else if (pos < 0 && lphost.length() > 0)
		{
			int lastlen = lphost.length();
			*lpdnsname = lastlen;
			lpdnsname++;
			memcpy(lpdnsname, lphost.c_str(), lastlen);
			lpdnsname += lastlen;
			break;
		}
		else {
			string strip = HttpUtils::ip2str(dnsserver);
			log("%s %d host:%s dnsserver:%s error\r\n",__FUNCTION__, __LINE__, host.c_str(),strip.c_str());
			return 0;
		}
	}

	*(lpdnsname) = 0;
	lpdnsname++;
	LPDNSTYPECLASS lptype = (LPDNSTYPECLASS)lpdnsname;
	lptype->dnstype = 0x0100;
	lptype->dnsclass = 0x0100;
	lpdnsname = (char*)lptype + sizeof(DNSTYPECLASS);

	int sendlen = lpdnsname - dnsbuf;

	int dnssock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (dnssock == INVALID_SOCKET)
	{
		string strip = HttpUtils::ip2str(dnsserver);
		log("%s %d host:%s dnsserver:%s error\r\n", __FUNCTION__, __LINE__, host.c_str(), strip.c_str());
		return FALSE;
	}

#define SOCKET_ASYNC_OPT
#define SOCKET_ASYNC_IOCTL

#ifdef SOCKET_ASYNC_OPT
		int timeout = 1000;
		ret = setsockopt(dnssock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
#else
		u_long mode = 1;
		ret = ioctlsocket(dnssock, FIONBIO, &mode) ;
#endif
	

	sockaddr_in si = { 0 };
	si.sin_port = ntohs(DNS_PORT);
	si.sin_family = AF_INET;
	si.sin_addr.S_un.S_addr = dnsserver ;

	int sendsize = sendto(dnssock, dnsbuf, sendlen, 0, (sockaddr*)&si, sizeof(sockaddr_in));
	if (sendsize != sendlen)
	{
		closesocket(dnssock);
		string strip = HttpUtils::ip2str(dnsserver);
		log("%s %d host:%s dnsserver:%s error\r\n", __FUNCTION__, __LINE__, host.c_str(), strip.c_str());
		return FALSE;
	}

	int sockaddrlen = sizeof(sockaddr_in);
	
#ifdef SOCKET_ASYNC_OPT
	int recvsize = recvfrom(dnssock, dnsbuf, sizeof(dnsbuf), 0, (sockaddr*)&si, &sockaddrlen);
#else
	int time = 0;
	int recvsize = 0;
	while (time < 200) {
		recvsize = recvfrom(dnssock, dnsbuf, sizeof(dnsbuf), 0, (sockaddr*)&si, &sockaddrlen);
		if (recvsize > 0) {
			break;
		}
		else {
			Sleep(20);
			time += 20;
		}
	}
#endif
	closesocket(dnssock);
	if (recvsize <= 0)
	{
		string strip = HttpUtils::ip2str(dnsserver);
		log("%s %d host:%s dnsserver:%s error\r\n", __FUNCTION__, __LINE__, host.c_str(), strip.c_str());
		return 0;
	}

	DWORD dwip = 0;
	//int answersize = recvsize - (lpdnsname - dnsbuf);
	LPDNSANSWERHEADER lpanswer = (LPDNSANSWERHEADER)lpdnsname;
	while (((char*)lpanswer < dnsbuf + recvsize))
	{
		if (lpanswer->AddrLen == 0x400 && lpanswer->Type == 0x100 /*&& lpanswer->Class == 0x100*/)
		{
			dwip = *(DWORD*)((char*)lpanswer + sizeof(DNSANSWERHEADER));
			break;
		}
		else {
			int answerlen = ntohs(lpanswer->AddrLen);
			if (answerlen > DNS_PACKET_LIMIT || answerlen <= 0)
			{
				break;
			}
			lpanswer = (LPDNSANSWERHEADER)((char*)lpanswer + sizeof(DNSANSWERHEADER) + answerlen);
		}
	}

	if (dwip == 0) {
		string strip = HttpUtils::ip2str(dnsserver);
		log("%s %d host:%s dnsserver:%s error\r\n", __FUNCTION__, __LINE__, host.c_str(), strip.c_str());
	}
	return dwip;
}
