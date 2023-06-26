

#include <windows.h>
#include <WinSock2.h>
#include <stdio.h>
#include <iostream>
#include <DbgHelp.h>
#include "NetCardInfo.h"
#include "Public.h"
//can not be #pragma comment(lib,"../lib/ssleay32.lib") why?
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"dbghelp.lib")
#pragma comment(lib,"Iphlpapi.lib")

using namespace std;



int main() {

	int	nRetCode = 0;

	char curdir[MAX_PATH] = { 0 };
	nRetCode = GetCurrentDirectoryA(MAX_PATH, curdir);
	string curPath = string(curdir) + "\\";

	WORD wVersionRequested = MAKEWORD(2, 2);
	WSADATA wsaData = { 0 };
	if (WSAStartup(wVersionRequested, &wsaData) != 0)
	{
		printf("WSAStartup error,error code is:%d\n", GetLastError());
		getchar();
		return -1;
	}


	int	iInterfaceCnt = 0;
	PIP_ADAPTER_INFO padpterInfo = NetCardInfo::ShowNetCardInfo(&iInterfaceCnt);
	if (padpterInfo == FALSE)
	{
		getchar();
		return FALSE;
	}

	printf("ÇëÊäÈëarp¹¥»÷µÄÍø¿¨ÐòºÅ(1-%d):", iInterfaceCnt);
	int			iChooseNum = 0;
	scanf_s("%d", &iChooseNum);
	printf("\n");
	if (iChooseNum < 1 || iChooseNum > iInterfaceCnt)
	{
		printf("Interface number out of range\n");
		getchar();
		return -1;
	}
	PIP_ADAPTER_INFO pAdapter = NetCardInfo::GetNetCardAdapter(padpterInfo, iChooseNum - 1);

	unsigned long gLocalIP = inet_addr(pAdapter->IpAddressList.IpAddress.String);
	string tmp = Public::formatIP(gLocalIP);
	printf("local ip:%s\r\n", tmp.c_str());

	unsigned long gGatewayIP = inet_addr(pAdapter->GatewayList.IpAddress.String);
	tmp = Public::formatIP(gGatewayIP);
	printf("gateway ip:%s\r\n", tmp.c_str());

	unsigned char gLocalMAC[6];
	memmove(gLocalMAC, pAdapter->Address, MAC_ADDRESS_SIZE);
	tmp = Public::formatMAC(gLocalMAC);
	printf("local mac:%s\r\n", tmp.c_str());



	unsigned long gNetMask = inet_addr(pAdapter->IpAddressList.IpMask.String);
	tmp = Public::formatIP(gNetMask);
	printf("subnet mask:%s\r\n", tmp.c_str());

	unsigned long gNetMaskIP = gNetMask & gGatewayIP;
	tmp = Public::formatIP(gNetMaskIP);
	printf("net mask ip:%s\r\n", tmp.c_str());

	char gDevName[256] = { 0 };
	lstrcpyA(gDevName, pAdapter->AdapterName);
	printf("net card name:%s\r\n", gDevName);

	int gNetcardIndex = pAdapter->Index;
	printf("net card index:%d\r\n", gNetcardIndex);

	string devdescp = pAdapter->Description;

	GlobalFree((char*)padpterInfo);

}