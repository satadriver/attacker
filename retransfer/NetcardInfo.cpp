

#include <winsock2.h>
#include <windows.h>
#include <Iptypes.h >
#include <iphlpapi.h>
#include "NetCardInfo.h"
#include "retransfer.h"
#include "HttpUtils.h"
#include "initor.h"

string NetCardInfo::selectWeapon(unsigned long * localIP, unsigned long * netmask, unsigned long * netgateip, unsigned char * lpmac, string tips) {
	int	iInterfaceCnt = 0;
	PIP_ADAPTER_INFO padpterInfo = NetCardInfo::ShowNetCardInfo(&iInterfaceCnt);
	if (padpterInfo == FALSE)
	{
		getchar();
		return "";
	}

	printf("%s(1-%d):", tips.c_str(), iInterfaceCnt);
	int			iChooseNum = 0;
	scanf_s("%d", &iChooseNum);
	printf("\n");
	if (iChooseNum < 1 || iChooseNum > iInterfaceCnt)
	{
		printf("Interface number out of range\n");
		getchar();
		return "";
	}
	PIP_ADAPTER_INFO pAdapter = NetCardInfo::GetNetCardAdapter(padpterInfo, iChooseNum - 1);

	string adaptername = pAdapter->AdapterName;
	*localIP = inet_addr(pAdapter->IpAddressList.IpAddress.String);
	*netmask = inet_addr(pAdapter->IpAddressList.IpMask.String);
	*netgateip = inet_addr(pAdapter->GatewayList.IpAddress.String);
	memmove(lpmac, pAdapter->Address, MAC_ADDRESS_SIZE);


	printf("get ip:%s,mac:%s,netmask:%s,gatewayip:%s\r\n", HttpUtils::getIPstr(*localIP).c_str(),
		Init::getmac(lpmac).c_str(), HttpUtils::getIPstr(*netmask).c_str(),
		HttpUtils::getIPstr(*netgateip).c_str());
	GlobalFree((char*)padpterInfo);
	return adaptername;
}



PIP_ADAPTER_INFO NetCardInfo::ShowNetCardInfo(int *count) {
	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO*)GlobalAlloc(GPTR, sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL)
	{
		printf("ShowNetCardInfo GlobalAlloc error\r\n");
		return FALSE;
	}

	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW)
	{
		GlobalFree((char*)pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO *)GlobalAlloc(GPTR, ulOutBufLen);
		if (pAdapterInfo == NULL)
		{
			printf("ShowNetCardInfo GetAdaptersInfo first error\r\n");
			return FALSE;
		}
	}

	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == NO_ERROR)
	{
		int number = 0;
		PIP_ADAPTER_INFO pAdapter = 0;
		printf("本机安装的网卡列表如下:\r\n");
		for (pAdapter = pAdapterInfo; pAdapter != NULL; pAdapter = pAdapter->Next)
		{
			/*
			if(pAdapter->Type != MIB_IF_TYPE_ETHERNET && pAdapter->Type !=  IF_TYPE_IEEE80211)
			{
			continue;
			}

			if(pAdapter->AddressLength != MAC_ADDRESS_SIZE)
			{
			continue;
			}
			if (lstrlenA(pAdapter->IpAddressList.IpAddress.String) < 8 || lstrlenA(pAdapter->GatewayList.IpAddress.String) < 8)
			{
			continue;
			}

			if (RtlCompareMemory(pAdapter->IpAddressList.IpAddress.String,"0.0.0.0",7) != 7 && RtlCompareMemory(pAdapter->GatewayList.IpAddress.String,"0.0.0.0",7) != 7)
			{
			break;
			}
			*/
			number++;
			printf("网卡号码:\t%d\r\n网卡名称:\t%s\r\n网卡描述:\t%s\r\n网卡类型:\t%d\r\n网卡IP地址:\t%s\r\n网关IP地址:\t%s\r\n\r\n",
				number, pAdapter->AdapterName, pAdapter->Description, pAdapter->Type, pAdapter->IpAddressList.IpAddress.String,
				pAdapter->GatewayList.IpAddress.String);
		}

		*count = number;
		//GlobalFree((char*)pAdapterInfo); 
		return pAdapterInfo;
	}
	else
	{
		printf("GetNetCardInfo GetAdaptersInfo second error\r\n");
		GlobalFree((char*)pAdapterInfo);
		return FALSE;
	}
}




PIP_ADAPTER_INFO NetCardInfo::GetNetCardAdapter(PIP_ADAPTER_INFO pAdapterInfo, int seq) {

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