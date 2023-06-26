
#pragma once
#include <vector>
#include <iostream>
#include <unordered_map>

#include <string>

using namespace std;

#pragma pack(1)

typedef struct {
	int sock;
	sockaddr_in sa;
	char *data;
	int datalen;
}DNS_REPLY_PARAMS,*LPDNS_REPLY_PARAMS;

#pragma pack()



class DnsProxy{
public:
	unordered_map <string, char * >gDnsResultMap;



	SOCKET mSockDns;
	
	SOCKET	mSockQuery;

	unsigned long mServerip;

	DnsProxy *mInstance;

	DnsProxy( unsigned long serverip);
	~DnsProxy();



	static int __stdcall DnsProxyListener(DnsProxy*instance);



	int createQuerySock(int time);

	static unsigned int getIPFromDNS(const char * dnsbuf, int sendlen, char * data, DnsProxy*);

};
