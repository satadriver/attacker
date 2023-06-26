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



class DnsKeeper {
public:
	DnsKeeper * mInstance;
	CRITICAL_SECTION mCS;
	unordered_map <string, DOMAININFO> gDnsKeeperMap;

	DnsKeeper();
	~DnsKeeper();

	static unsigned int getIPFromDomainName(string ip);

	static unsigned long getDnsFromMap(string dns);

};