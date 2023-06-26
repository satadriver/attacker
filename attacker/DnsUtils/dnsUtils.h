#pragma once

#include <iostream>
#include <string>
#include <vector>

using namespace std;

#define DNS_LOG_FILENAME "dns.log"
#define DNS_QUERY_TIMEOUT 1

class DnsUitls {
public:
	DnsUitls(vector<string> dnses);
	~DnsUitls();

	DnsUitls * mInstance;

	static int DnsUitls::getDnsName(char * dns, char * dnsname);
	static int DnsUitls::isTargetDNS(char * dns);

	static string host2Dns(string host);

	static string dns2Host(char * dns);
};