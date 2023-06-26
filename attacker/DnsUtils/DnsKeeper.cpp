

#include <windows.h>
#include "../attacker.h"
#include "../ssl/sslPublic.h"
#include "DnsKeeper.h"
#include "../Packet.h"
#include "../utils/lock.h"


DnsKeeper *gDnsKeeper = 0;

DnsKeeper::~DnsKeeper() {

}


DnsKeeper::DnsKeeper() {
	if (gDnsKeeper)
	{
		return;
	}
	mInstance = this;
	gDnsKeeper = this;

	gDnsKeeperMap.clear();

	InitializeCriticalSection(&mCS);
}

unsigned long DnsKeeper::getDnsFromMap(string dns){
	
	int ret = 0;

	unsigned long ip = 0;

	__try
	{
		EnterCriticalSection(&gDnsKeeper->mCS);

		unordered_map <string, DOMAININFO >::iterator it = gDnsKeeper->gDnsKeeperMap.find(dns);
		if (it != gDnsKeeper->gDnsKeeperMap.end() )
		{
			ip = it->second.ip;
		}

		LeaveCriticalSection(&gDnsKeeper->mCS);

		if (ip)
		{
			return ip;
		}

		ip = getIPFromDomainName(dns);
		if (ip)
		{
			DOMAININFO info = { 0 };
			info.dnstime = time(0);
			info.ip = ip;

			EnterCriticalSection(&gDnsKeeper->mCS);

			it = gDnsKeeper->gDnsKeeperMap.find(dns);
			if (it != gDnsKeeper->gDnsKeeperMap.end() )
			{
				it->second.dnstime = info.dnstime;
				it->second.ip = ip;
			}
			else {
				pair< std::unordered_map<string, DOMAININFO>::iterator, bool > retit;
				retit = gDnsKeeper->gDnsKeeperMap.insert(pair<string, DOMAININFO>(dns, info));
				if (retit.second == 0)
				{
					printf("DnsKeeper insert ip:%x,dns:%s error:%u\r\n", ip, dns.c_str(), GetLastError());
				}
			}

			LeaveCriticalSection(&gDnsKeeper->mCS);
		}
		else {
			char szout[1024];
			wsprintfA(szout,"getIPFromDomainName:%s error\r\n", dns.c_str());
			Public::WriteLogFile(szout);
			printf(szout);
		}
	}
	__except(1) 
	{
		printf("getDnsFromMap exception\r\n");
		Public::WriteLogFile("getDnsFromMap exception\r\n");
	}
	
	return ip;
}




unsigned int DnsKeeper::getIPFromDomainName(string querydns) {
	int ret = 0;

	char dnsbuf[DNS_PACKET_LIMIT+64] = { 0 };
	LPDNSHEADER dnshdr = (LPDNSHEADER)dnsbuf;
	dnshdr->TransactionID = LOCAL_QUERY_DNS_ID;
	dnshdr->Flags = 1;
	dnshdr->Questions = 0x100;
	dnshdr->AdditionalRRS = 0;
	dnshdr->AnswerRRS = 0;
	dnshdr->AuthorityRRS = 0;

	char * dnsname = dnsbuf + sizeof(DNSHEADER);
	char * lpdnsname = dnsname;
	string dns = querydns;
	while (1)
	{
		int pos = dns.find(".");
		if (pos == 0)
		{
			dns = dns.substr(1);
		}
		else if (pos > 0)
		{
			string sub = dns.substr(0, pos);
			int sublen = sub.length();
			*lpdnsname = sublen;
			lpdnsname++;
			memcpy(lpdnsname, sub.c_str(), sublen);
			lpdnsname += sublen;
			dns = dns.substr(pos + 1);
		}
		else if (pos < 0 && dns.length() > 0)
		{
			int lastlen = dns.length();
			*lpdnsname = lastlen;
			lpdnsname++;
			memcpy(lpdnsname, dns.c_str(), lastlen);
			lpdnsname += lastlen;
			break;
		}
		else {
			printf("parse dns name error:%s\r\n", querydns.c_str());
			break;
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
		return FALSE;
	}

	int timeout = 20;
	ret = setsockopt(dnssock, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));

	sockaddr_in si = { 0 };
	si.sin_port = ntohs(DNS_PORT);
	si.sin_family = AF_INET;
	si.sin_addr.S_un.S_addr = LOCAL_DNS_QUERY_SERVER;

	int sendret = sendto(dnssock, dnsbuf, sendlen, 0, (sockaddr*)&si, sizeof(sockaddr_in));
	if (sendret != sendlen)
	{
		closesocket(dnssock);
		return FALSE;
	}


	int sockaddrlen = sizeof(sockaddr_in);
	int recvsize = recvfrom(dnssock, dnsbuf, DNS_PACKET_LIMIT, 0, (sockaddr*)&si, &sockaddrlen);
	if (recvsize <= sendlen)
	{
		closesocket(dnssock);
		return FALSE;
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

	closesocket(dnssock);
	return dwip;
}
