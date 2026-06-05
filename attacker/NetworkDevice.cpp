

#include <winsock2.h>
#include <windows.h>
#include <Iptypes.h >
#include <iphlpapi.h>
#include "Public.h"
#include "NetworkDevice.h"
#include "attacker.h"
#include "FileOper.h"
#include "HttpUtils.h"
#include "utils/Tools.h"
#include "config.h"


#define NETCARD_SELECTED_FILE	"cardNum.conf"


string NetworkDevice::ChooseNetcard(unsigned long* localip, unsigned long* mask, unsigned long* gate,unsigned char* mac,
	int& cardNum,unsigned long*dnsserver) 
{
	int	num = 0;
	PIP_ADAPTER_INFO padpterInfo = DisplayNetCard(&num);
	if (padpterInfo == FALSE)
	{
		return "";
	}

	if (cardNum == -1)
	{
		do {
			printf("%s(1-%d):", "ÇëÑ¡Ôñ×¥°üÍø¿¨ÐòºÅ", num);
			scanf_s("%d", &cardNum);
			printf("\n");
			if (cardNum < 1 || cardNum > num) {
				printf("Interface number out of range\n");
			}
		} while (cardNum < 1 || cardNum > num);	
	}

	PIP_ADAPTER_INFO pAdapter = GetNetCardAdapter(padpterInfo, cardNum - 1);
	if (pAdapter == 0) {
		return "";
	}
	string adaptername = pAdapter->AdapterName;
	*localip = inet_addr(pAdapter->IpAddressList.IpAddress.String);
	*mask = inet_addr(pAdapter->IpAddressList.IpMask.String);
	*gate = inet_addr(pAdapter->GatewayList.IpAddress.String);
	memmove(mac, pAdapter->Address, MAC_ADDRESS_SIZE);
	string aliasname = getAdapterAlias(adaptername);

	ULONG pail = 0;
	GetPerAdapterInfo(pAdapter->Index, NULL, &pail);
	PIP_PER_ADAPTER_INFO pai =(PIP_PER_ADAPTER_INFO)malloc(pail);
	if (GetPerAdapterInfo(pAdapter->Index, pai,&pail) == NO_ERROR) {
		PIP_ADDR_STRING dns = &(pai->DnsServerList);
		while (dns) {
			if (strcmp(dns->IpAddress.String, "0.0.0.0") != 0) {
				*dnsserver = inet_addr( dns->IpAddress.String);
				printf("dns server:%s\r\n", dns->IpAddress.String);
			}
			dns = dns->Next;
		}
	}

	GlobalFree((char*)padpterInfo);

	printf("select netcard:%s,name:%s,ip:%s,mac:%s,netmask:%s,gatewayip:%s\r\n",
		aliasname.c_str(), adaptername.c_str(), HttpUtils::getIPstr(*localip).c_str(),
		HttpUtils::getmac(mac).c_str(), HttpUtils::getIPstr(*mask).c_str(),
		HttpUtils::getIPstr(*gate).c_str());

	char cardno[256];
	//int cardnolen = wsprintfA(szcardno, "%d", cardNum);
	//FileOper::fileWriter(NETCARD_SELECTED_FILE, (const char*)szcardno, cardnolen, TRUE);
	wsprintfA(cardno, "%d", cardNum);
	Config::reviseConfig(CONFIG_FILENAME,"netcard", cardno);

	return adaptername;
}



PIP_ADAPTER_INFO NetworkDevice::DisplayNetCard(int* count) {
	ULONG bufsize = sizeof(IP_ADAPTER_INFO);
	PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO*)GlobalAlloc(GPTR, sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL)
	{
		log("%s %d error\r\n",__FUNCTION__,__LINE__);
		return FALSE;
	}

	if (GetAdaptersInfo(pAdapterInfo, &bufsize) == ERROR_BUFFER_OVERFLOW)
	{
		GlobalFree((char*)pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO*)GlobalAlloc(GPTR, bufsize);
		if (pAdapterInfo == NULL)
		{
			log("%s %d error\r\n", __FUNCTION__, __LINE__);
			return FALSE;
		}
	}

	if (GetAdaptersInfo(pAdapterInfo, &bufsize) == NO_ERROR)
	{
		int number = 0;
		PIP_ADAPTER_INFO pAdapter = 0;
		printf("±¾»úËùÓÐÍø¿¨ÈçÏÂ:\r\n");
		for (pAdapter = pAdapterInfo; pAdapter != NULL; pAdapter = pAdapter->Next)
		{
			number++;

			string aliasname = getAdapterAlias(pAdapter->AdapterName);

			printf(
				"Íø¿¨ºÅÂë:\t%d\r\nÍø¿¨Ãû³Æ:\t%s\r\nÍø¿¨±ðÃû:\t%s\r\nÍø¿¨ÃèÊö:\t%s\r\nÍø¿¨ÀàÐÍ:\t%d\r\nÍø¿¨IPµØÖ·:\t%s\r\nÍø¹ØIPµØÖ·:\t%s\r\n\r\n",
				number, pAdapter->AdapterName, aliasname.c_str(), pAdapter->Description,
				pAdapter->Type, pAdapter->IpAddressList.IpAddress.String,
				pAdapter->GatewayList.IpAddress.String);
		}

		*count = number;
		return pAdapterInfo;
	}
	else
	{
		log("%s %d error\r\n", __FUNCTION__, __LINE__);
		GlobalFree((char*)pAdapterInfo);
		return FALSE;
	}
}


string NetworkDevice::getAdapterAlias(string adaptername) {
	unsigned char szalias[MAX_PATH] = { 0 };
	//subkey can not be \\SYSTEM,why?
	string subkey = "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\" + 
		adaptername + "\\Connection\\";

	int cpubits = Tools::getSysBits();
	int ret = Tools::QueryRegistryValue(HKEY_LOCAL_MACHINE, (char*)subkey.c_str(), "Name", szalias, cpubits);
	if (ret)
	{
		return string((char*)szalias);
	}

	return "";
}



PIP_ADAPTER_INFO NetworkDevice::GetNetCardAdapter(PIP_ADAPTER_INFO pAdapterInfo, int seq) {

	PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
	for (int number = 0; number < seq; pAdapter = pAdapter->Next, number++)
	{
		if (pAdapter == NULL)
		{
			return FALSE;
		}
	}
	return pAdapter;
}


#include <ws2tcpip.h>

int GetAllAddress(vector<unsigned long> &ips) {

	ULONG bufferSize = sizeof(PIP_ADAPTER_ADDRESSES);
	PIP_ADAPTER_ADDRESSES pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(bufferSize);
	if (pAddresses == NULL) {
		log("%s %d error\r\n",__FUNCTION__,__LINE__);
		return -1;
	}

	DWORD result = GetAdaptersAddresses(
		AF_UNSPEC,          
		GAA_FLAG_INCLUDE_PREFIX,
		NULL,
		pAddresses,
		&bufferSize
	);

	if (result == ERROR_BUFFER_OVERFLOW) {
		free(pAddresses);
		pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(bufferSize);
		if (pAddresses == NULL) {
			log("%s %d error\r\n", __FUNCTION__, __LINE__);
			return 1;
		}
		result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &bufferSize);
	}

	if (result != NO_ERROR) {
		log("%s %d error\r\n", __FUNCTION__, __LINE__);
		free(pAddresses);
		return -1;
	}

	PIP_ADAPTER_ADDRESSES pAdapter = pAddresses;
	while (pAdapter) {
		if (pAdapter->OperStatus == IfOperStatusUp) {
			PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pAdapter->FirstUnicastAddress;
			while (pUnicast) {
				char ipAddress[INET6_ADDRSTRLEN];
				SOCKADDR* pSockAddr = pUnicast->Address.lpSockaddr;
				if (pSockAddr->sa_family == AF_INET) {
					struct sockaddr_in* pIPv4 = (struct sockaddr_in*)pSockAddr;
					inet_ntop(AF_INET, &(pIPv4->sin_addr), ipAddress, INET6_ADDRSTRLEN);
					printf("%-20s %-15s %-10s\n", pAdapter->FriendlyName, ipAddress, "IPv4");
					ips.push_back(pIPv4->sin_addr.S_un.S_addr);
				}
				else if (pSockAddr->sa_family == AF_INET6) {
					struct sockaddr_in6* pIPv6 = (struct sockaddr_in6*)pSockAddr;
					inet_ntop(AF_INET6, &(pIPv6->sin6_addr), ipAddress, INET6_ADDRSTRLEN);
					printf("%-20s %-15s %-10s\n", pAdapter->FriendlyName, ipAddress, "IPv6");
					//ips.push_back(pIPv6->sin6_addr.u);
				}

				pUnicast = pUnicast->Next;
			}
		}
		pAdapter = pAdapter->Next;
	}

	free(pAddresses);
	return 0;
}
