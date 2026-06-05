

#ifndef NETCARDINFO_H_H_H
#define NETCARDINFO_H_H_H

#include <Windows.h>
#include <iptypes.h>
#include <string>


using namespace std;

int GetAllAddress(vector<unsigned long>& ips);

class NetworkDevice {
public:
	static PIP_ADAPTER_INFO DisplayNetCard(int *);
	static PIP_ADAPTER_INFO GetNetCardAdapter(PIP_ADAPTER_INFO pAdapterInfo, int seq);
	static string getAdapterAlias(string adaptername);
	static string ChooseNetcard(unsigned long * localip,unsigned long * mask,unsigned long * gate,unsigned char *mac,
		int & num,unsigned long *dnsserver);
};

#endif