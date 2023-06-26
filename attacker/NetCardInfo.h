

#ifndef NETCARDINFO_H_H_H
#define NETCARDINFO_H_H_H

class NetCardInfo {
public:
	static PIP_ADAPTER_INFO ShowNetCardInfo(int *);
	static PIP_ADAPTER_INFO GetNetCardAdapter(PIP_ADAPTER_INFO pAdapterInfo, int seq);
	static string NetCardInfo::getAdapterAlias(string adaptername);
	static string NetCardInfo::selectNetcard(unsigned long * localIP,unsigned long * netmask,unsigned long * netgate,unsigned char *,
		int & selectedcard);
};

#endif