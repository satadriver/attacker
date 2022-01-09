
#include "initor.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "HttpUtils.h"

int Init::openPortInFW(unsigned int port,string name,string protocol) {

	//int iRet = WinExec("cmd /c net stop mpssvc",SW_HIDE);
	//int iRet = WinExec("cmd /c netsh advfirewall set privateprofile state off",SW_HIDE);
	//iRet = WinExec("cmd /c netsh advfirewall set publicprofile state off",SW_HIDE);

	char szCmd[1024];
	
	wsprintfA(szCmd, "netsh advfirewall firewall add rule name=\"%s\" protocol=%s dir=in localport=%u action=allow",name.c_str(),protocol.c_str(),port);
	//wsprintfA(szCmd, "netsh firewall set portopening TCP %u ENABLE", port);
	int iRet = system(szCmd);
	if (iRet )
	{
		printf("open port:%u in firewall error\r\n", port);
		return FALSE;
	}

	printf("open port:%u in firewall ok\r\n", port);
	return 0;
}



string Init::getmac(unsigned char * mac) {
	char szmac[64];
	wsprintfA(szmac, "%x-%x-%x-%x-%x-%x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return string(szmac);
}



string Init::getTargetInfo(unsigned char * mac,unsigned long ip, unsigned short port) {
	string strmac = getmac(mac);
	string strip = HttpUtils::getIPstr(ip);
	char szinfo[1024];
	wsprintfA(szinfo, "mac:%s,ip:%s,port:%u\r\n", strmac.c_str(), strip.c_str(), port);

	return string(szinfo);
}