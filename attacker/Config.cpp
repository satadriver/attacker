

#include "Confiig.h"
#include "FileOper.h"
#include "Public.h"
#include <winsock2.h>
#include "attacker.h"
#include <algorithm>
#include "HttpUtils.h"
#include "DnsUtils/dnsUtils.h"
#include "Utils/AscHex.h"
#include "../DnsUtils/DnsServer.h"



vector<string> Config::parseAttackCfg(string fn, unsigned long* serverip, int* speed, int* opensslflag, int* runmode, char* gwmac, string& servername) {
	char* buf = 0;
	int fs = 0;

	printf("parsing config file:%s\r\n", fn.c_str());

	vector <string> dnslist;
	dnslist.clear();

	int ret = FileOper::fileReader(fn, &buf, &fs);
	if (ret <= 0) {
		return dnslist;
	}

	int cfglen = Public::removespace(buf, buf);
	string str = string(_strlwr(buf), cfglen);

	delete buf;

	string substr = "";
	int endtag = 0;
	while (1) {
		int linepos = str.find(CRLN);
		if (linepos >= 0) {
			substr = str.substr(0, linepos);
			str = str.substr(linepos + strlen(CRLN));
		}
		else {
			linepos = str.find(CRLNLINUX);
			if (linepos >= 0) {
				substr = str.substr(0, linepos);
				str = str.substr(linepos + strlen(CRLNLINUX));
			}
			else {
				substr = str;
				str = "";
				endtag = 1;
			}
		}

		if (substr.length() > 0 && (( substr.at(0) == '#') || (substr.at(0) == '/'&& substr.at(1) == '/') ) )
		{
			continue;
		}

		const char* end = 0;
		const char* hdr = 0;
		char* speedhdr = "speed=";
		string opensslcfg = "opensslcfg=";
		string dnsserver = "dataserver=";
		char* mode = "mode=";
		char* username = "username=";
		char* macaddr = "gatewaymac=";

		hdr = strstr(substr.c_str(), "[");
		if (hdr > 0) {
			hdr += strlen("[");
			end = strstr(hdr, "]");
			if (end > 0 && (end - hdr > 0)) {

				string value = string(hdr, end - hdr);

				int pos = value.find(dnsserver);
				if (pos != std::string::npos) {
					value.replace(pos, dnsserver.length(), "");
					if (value == "auto")
					{
						*serverip = 0;
						printf("get config server ip:%s\r\n", value.c_str());
					}
					else {
						servername = value;
						if (HttpUtils::isAscIP(value))
						{
							//parse ip error return 0xffffffff
							*serverip = inet_addr(value.c_str());
						}
						else {
							do
							{
								*serverip = DnsServer::DnsQuery(value,DNS_SERVER_ADDRESS);
								if (*serverip == -1 || *serverip == 0)
								{
									Sleep(1000);
								}
								else {
									break;
								}
							} while (*serverip == -1 || *serverip == 0);
						}

						printf("config server:%s ip:%x\r\n", value.c_str(), *serverip);
					}
				}
				else if (memcmp(value.c_str(), opensslcfg.c_str(), opensslcfg.length()) == 0)
				{
					string opensslconfig = value.substr(opensslcfg.length());
					*opensslflag = atoi(opensslconfig.c_str());
					printf("config openssl param:%d\r\n", *opensslflag);
				}
				else if (memcmp(value.c_str(), speedhdr, strlen(speedhdr)) == 0)
				{
					string strspeed = value.substr(strlen(speedhdr));
					*speed = atoi(strspeed.c_str());
					printf("config winpcap param:%d\r\n", *speed);
				}
				else if (memcmp(value.c_str(), mode, strlen(mode)) == 0)
				{
					string strmode = value.substr(strlen(mode));
					*runmode = atoi(strmode.c_str());
					printf("config attack mode:%d\r\n", *runmode);
				}
				else if (memcmp(value.c_str(), username, strlen(username)) == 0)
				{
					string struser = value.substr(strlen(username));
					lstrcpyA(G_USERNAME, struser.c_str());
					printf("config user name:%s\r\n", G_USERNAME);
				}
				else if (memcmp(value.c_str(), macaddr, lstrlenA(macaddr)) == 0)
				{
					string strmac = value.substr(strlen(macaddr));
					while (1) {
						int p = strmac.find("-");
						if (p >= 0)
						{
							strmac = strmac.replace(p, 1, "");
						}
						else {
							break;
						}
					}

					unsigned char dbmac[64] = { 0 };
					AscHex::asc2hex((unsigned char*)strmac.c_str(), strmac.length(), dbmac);
					memcpy(gwmac, (char*)dbmac, 6);
					printf("config gateway mac:%s\r\n", strmac.c_str());
				}
				else {
					dnslist.push_back(value);
					//printf("config host:%s\r\n", value.c_str());
				}
			}
		}

		if (endtag > 0) {
			break;
		}

		continue;
	}

	return dnslist;
}




int Config::parseDnsCfg(string fn, vector <string>& dns) {
	int cnt = 0;

	char* buf = 0;
	int fs = 0;

	printf("parsing dns file:%s\r\n", fn.c_str());

	int ret = FileOper::fileReader(fn, &buf, &fs);
	if (ret <= 0) {
		return 0;
	}

	int cfglen = Public::removespace(buf, buf);
	string str = string(buf, cfglen);
	delete buf;

	string substr = "";
	int flag = 0;
	while (1) {
		int linepos = str.find(CRLN);
		if (linepos >= 0) {
			substr = str.substr(0, linepos);
			str = str.substr(linepos + strlen(CRLN));
		}
		else {
			linepos = str.find(CRLNLINUX);
			if (linepos >= 0) {
				substr = str.substr(0, linepos);
				str = str.substr(linepos + strlen(CRLNLINUX));
			}
			else {
				substr = str;
				str = "";
				flag = 1;
			}
		}
		if (substr.length() > 0 && ((substr.at(0) == '#') || (substr.at(0) == '/' && substr.at(1) == '/')))
		{
			continue;
		}
		const char* end = 0;
		const char* hdr = 0;

		hdr = strstr(substr.c_str(), "[");
		if (hdr > 0) {
			hdr += strlen("[");
			end = strstr(hdr, "]");
			if (end > 0 && (end - hdr > 0)) {
				string value = string(hdr, end - hdr);
				dns.push_back(value);
				//printf("config dns:%s\r\n", value.c_str());
				cnt++;
			}
		}

		if (flag > 0) {
			break;
		}

		continue;
	}

	return cnt;

}






int Config::shiftDnsFormat(vector<string>& dnses) {
	for (unsigned int i = 0; i < dnses.size(); i++) {

		string old = dnses[i];
		if (old.length() <= 0) {
			dnses.erase(dnses.begin() + i);
			continue;
		}

		string newstr = DnsUitls::host2Dns(old);
		dnses[i] = newstr;
	}

	sort(dnses.begin(), dnses.end());  
	auto iter = unique(dnses.begin(), dnses.end());
	dnses.erase(iter, dnses.end());

	return 0;
}

