
#include "dnsUtils.h"
#include <windows.h>
#include "../Public.h"

#define MAX_DNS_DOMAIN_NAME_SPLIT_SIZE 64


vector<string> gDnsTargets;


DnsUitls::DnsUitls(vector<string> dnses) {
	if (mInstance)
	{
		return;
	}
	mInstance = this;

	gDnsTargets = dnses;
}

DnsUitls::~DnsUitls() {

}


int DnsUitls::getDnsName(char * dnsname, char * ascname) {

	char * dns = dnsname;

	char * asc = ascname;

	while (1)
	{
		int sublen = *dns;

		if (sublen == 0  && *(asc - 1) == '.')
		{
			*(asc - 1) = 0;
			break;
		}
		else if (sublen > 0 && sublen < MAX_DNS_DOMAIN_NAME_SPLIT_SIZE)
		{
			dns++;
			for (int i = 0; i < sublen; i++)
			{
				if ((*(dns + i) >= '0' && *(dns + i) <= '9') ||
					(*(dns + i) >= 'a' && *(dns + i) <= 'z') ||
					(*(dns + i) >= 'A' && *(dns + i) <= 'Z') ||
					(*(dns + i) == '-' || *(dns + i) == '_'))
				{
					*(asc + i) = *(dns + i);
				}
				else {
					return 0;
				}
			}

			dns += sublen;
			asc += sublen;
			*asc = '.';
			asc++;
		}
		else {
			char szlog[1024];
			int len = sprintf(szlog, "parse dns name:%s error\r\n", dns);
			Public::WriteLogFile("dnserror.txt", szlog, len);
			return -1;
		}
	}

	return 0;
}


string DnsUitls::dns2Host(char * dns) {
	char szhost[256] = { 0 };
	int dnslen = lstrlenA(dns);
	if (dnslen >= 256)
	{
		return "";
	}

	for (int i = 0, j = 0; i < dnslen;)
	{
		int partlen = dns[i];
		if (partlen > 0 && partlen < 64)
		{
			memcpy(szhost + j, dns + i + 1, partlen);

			i += (partlen + 1);

			j += partlen;

			*(szhost + j) = '.';

			j++;
		}
		else {
			break;
		}
	}

	int hostlen = lstrlenA(szhost);
	if (hostlen > 0)
	{
		*(szhost + hostlen - 1) = 0;
	}

	return szhost;
}



string DnsUitls::host2Dns(string host) {
	string newstr = "";
	for (unsigned int j = 0; j < host.length(); ) {

		if (host.c_str()[j] == '.') {
			newstr.append((char*)&j);

			string tmp = host.substr(0, j);
			newstr.append(tmp);

			host = host.substr(j + 1);

			j = 0;
		}
		else {
			j++;
		}
	}

	if (host.length() > 0) {
		int k = host.length();
		newstr.append((char*)&k);
		newstr.append(host);
	}

	return newstr;
}


int DnsUitls::isTargetDNS(char * dns) {

	unsigned int targetlen = gDnsTargets.size();
	for (unsigned int i = 0; i < targetlen; i++) {
		if (strstr(dns, gDnsTargets[i].c_str())) {
			return TRUE;
		}
	}

	return 0;
}


