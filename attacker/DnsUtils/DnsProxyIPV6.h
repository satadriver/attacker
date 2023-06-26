#pragma once


#include <vector>
#include <iostream>
#include <unordered_map>
#include <ip6_misc.h>

#include <string>

using namespace std;

#pragma pack(1)

typedef struct {
	int sock;
	sockaddr_in6 sa;
	char *data;
	int datalen;
}DNSIPV6_REPLY_PARAMS, *LPDNSIPV6_REPLY_PARAMS;

#pragma pack()





class DnsProxyIPV6 {
public:
	unordered_map <string, char * >gDnsResultMap;


	SOCKET mSockDns ;

	SOCKET	mSockQuery;

	unsigned long mServerip;

	DnsProxyIPV6 *mInstance;

	DnsProxyIPV6(unsigned long serverip);
	~DnsProxyIPV6();

	static int __stdcall DnsProxyListener(DnsProxyIPV6*instance);

	int createQuerySock(int time);

	static unsigned int getIPFromDNS(const char * dnsbuf, int sendlen, char * data, DnsProxyIPV6*);

};
