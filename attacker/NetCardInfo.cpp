

#include <winsock2.h>
#include <windows.h>
#include <Iptypes.h >
#include <iphlpapi.h>
#include "Public.h"
#include "NetCardInfo.h"
#include "attacker.h"
#include "FileOper.h"
#include "HttpUtils.h"
#include "utils/Tools.h"





string NetCardInfo::selectWeapon(unsigned long * localIP,unsigned long * netmask,unsigned long * netgateip,
	unsigned char * lpmac,int & selectedcard) {
	int	iInterfaceCnt = 0;
	PIP_ADAPTER_INFO padpterInfo = NetCardInfo::ShowNetCardInfo(&iInterfaceCnt);
	if (padpterInfo == FALSE)
	{
		return "";
	}

	if (selectedcard == -1)
	{
		printf("%s(1-%d):", "请选择抓包网卡序号", iInterfaceCnt);
		scanf_s("%d", &selectedcard);
		printf("\n");
	}

	if (selectedcard < 1 || selectedcard > iInterfaceCnt)
	{
		printf("Interface number out of range\n");
		return "";
	}

	PIP_ADAPTER_INFO pAdapter = NetCardInfo::GetNetCardAdapter(padpterInfo, selectedcard - 1);

	string adaptername = pAdapter->AdapterName;
	*localIP = inet_addr(pAdapter->IpAddressList.IpAddress.String);
	*netmask = inet_addr(pAdapter->IpAddressList.IpMask.String);
	*netgateip = inet_addr(pAdapter->GatewayList.IpAddress.String);
	memmove(lpmac, pAdapter->Address, MAC_ADDRESS_SIZE);
	string aliasname = getAdapterAlias(adaptername);

	GlobalFree((char*)padpterInfo);

	printf("select netcard:%s,name:%s,ip:%s,mac:%s,netmask:%s,gatewayip:%s\r\n", 
		aliasname.c_str(),adaptername.c_str(), HttpUtils::getIPstr(*localIP).c_str(), 
		HttpUtils::getmac(lpmac).c_str(), HttpUtils::getIPstr(*netmask).c_str(),
		HttpUtils::getIPstr(*netgateip).c_str());

	//char szoption[1024];
	//int optionlen = wsprintfA(szoption, "%d", selectedcard);
	//FileOper::fileWriter("cardno.conf",szoption, optionlen,TRUE);
	
	char szcardno[1024];
	int cardnolen = wsprintfA(szcardno, "%d", selectedcard);
	FileOper::fileWriter("cardno.conf", (const char*)szcardno, cardnolen, TRUE);

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
			printf("ShowNetCardInfo GlobalAlloc error\r\n");
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
			number++;

			string aliasname = getAdapterAlias(pAdapter->AdapterName);

			printf("网卡号码:\t%d\r\n网卡名称:\t%s\r\n网卡别名:\t%s\r\n网卡描述:\t%s\r\n网卡类型:\t%d\r\n网卡IP地址:\t%s\r\n网关IP地址:\t%s\r\n\r\n",
				number, pAdapter->AdapterName, aliasname.c_str(),pAdapter->Description, pAdapter->Type, pAdapter->IpAddressList.IpAddress.String,
				pAdapter->GatewayList.IpAddress.String);
		}

		*count = number;
		return pAdapterInfo;
	}
	else
	{
		printf("GetNetCardInfo GetAdaptersInfo error\r\n");
		GlobalFree((char*)pAdapterInfo);
		return FALSE;
	}
}


string NetCardInfo::getAdapterAlias(string adaptername) {
	unsigned char szalias[MAX_PATH] = { 0 };
	//can not be \\SYSTEM,why?????
	string subkey = "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\" + adaptername + "\\Connection\\";

	int cpubits = Tools::GetCpuBits();
	int ret = Tools::QueryRegistryValue(HKEY_LOCAL_MACHINE, (char*)subkey.c_str(), "Name", szalias, cpubits);
	if (ret)
	{
		return string((char*)szalias);
	}

	return "";
}



PIP_ADAPTER_INFO NetCardInfo::GetNetCardAdapter(PIP_ADAPTER_INFO pAdapterInfo,int seq){
	
	PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
	for( int number = 0; number < seq ; pAdapter = pAdapter->Next,number ++) 
	{ 
		if (pAdapter == NULL)
		{
			return FALSE;
		}
	} 
	return pAdapter;
}