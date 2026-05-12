#pragma once

#include <unordered_map>
#include <windows.h>
#include <iostream>
#include "../utils/lock.h"

using namespace std;

#pragma pack(1)

typedef struct  
{
	unsigned long ip;
	time_t dnstime;
}DOMAININFO,*LPDOMAININFO;

#pragma pack()




#define DNS_VALID_TIME (24*60*60)



class DnsServer {
public:
	DnsServer* mInstance;
	CRITICAL_SECTION mCS;
	unordered_map <string, DOMAININFO> gDnsCenterMap;

	DnsServer();
	~DnsServer();

	static unsigned int DnsQuery(string ip,DWORD dnsserver);

	static unsigned long GetIPFromHost(string host);

};