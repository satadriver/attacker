

#include "Config.h"
#include "FileOper.h"
#include "Public.h"
#include <winsock2.h>
#include "attacker.h"
#include <algorithm>
#include "HttpUtils.h"
#include "DnsUtils/dnsUtils.h"
#include "Utils/AscHex.h"
#include "../DnsUtils/DnsServer.h"



vector<string> Config::parseAttackCfg(string fn, unsigned long* serverip, int* speed, int* openssl, int* mode, string& sign,string& servername,int &netcard,string &user,string& pw) {
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
		char* winpcapkey = "winpcap=";
		string opensslkey = "openssl=";
		string cardkey = "netcard=";
		string serverkey = "server=";
		char* modekey = "mode=";
		//char* mackey = "gateway=";
		char* userkey = "username=";
		string pwkey = "password=";
		char* signkey = "sign=";

		hdr = strstr(substr.c_str(), "[");
		if (hdr > 0) {
			hdr += strlen("[");
			end = strstr(hdr, "]");
			if (end > 0 && (end - hdr > 0)) {
				string value = string(hdr, end - hdr);
				int pos = value.find(serverkey);
				if (pos != std::string::npos) {
					value.replace(pos, serverkey.length(), "");
					if (value == "auto")
					{
						*serverip = 0;
						printf("config server ip:%s\r\n", value.c_str());
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
									Sleep(100);
								}
								else {
									break;
								}
							} while (*serverip == -1 || *serverip == 0);
						}
						printf("config server:%s ip:%x\r\n", value.c_str(), *serverip);
					}
				}
				else if (memcmp(value.c_str(), opensslkey.c_str(), opensslkey.length()) == 0)
				{
					string opensslconfig = value.substr(opensslkey.length());
					*openssl = atoi(opensslconfig.c_str());
					//printf("config openssl param:%d\r\n", *openssl);
				}
				else if (memcmp(value.c_str(), cardkey.c_str(), cardkey.length()) == 0)
				{
					string strcard = value.substr(cardkey.length());
					netcard = atoi(strcard.c_str());
					printf("config net card:%d\r\n",netcard);
				}
				else if (memcmp(value.c_str(), winpcapkey, strlen(winpcapkey)) == 0)
				{
					string strspeed = value.substr(strlen(winpcapkey));
					*speed = atoi(strspeed.c_str());
					//printf("config winpcap param:%d\r\n", *speed);
				}
				else if (memcmp(value.c_str(), modekey, strlen(modekey)) == 0)
				{
					string strmode = value.substr(strlen(modekey));
					*mode = atoi(strmode.c_str());
					//printf("config attack mode:%d\r\n", *mode);
				}
				else if (memcmp(value.c_str(), signkey, strlen(signkey)) == 0)
				{
					sign = value.substr(strlen(signkey));
					//printf("config attack mode:%d\r\n", *mode);
				}
				else if (memcmp(value.c_str(), pwkey.c_str(), pwkey.length()) == 0)
				{
					pw = value.substr(pwkey.length());
					//printf("config attack mode:%d\r\n", pw.c_str());
				}
				else if (memcmp(value.c_str(), userkey, strlen(userkey)) == 0)
				{
					user = value.substr(strlen(userkey));
					//lstrcpyA(G_USERNAME, user.c_str());
					//printf("config user name:%s\r\n", G_USERNAME);
				}
				/*
				else if (memcmp(value.c_str(), mackey, lstrlenA(mackey)) == 0)
				{
					string strmac = value.substr(strlen(mackey));
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
					//printf("config gateway mac:%s\r\n", strmac.c_str());
				}
				*/
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



int Config::reviseConfig(string fn, string  key,string value) {

	char* buf = 0;
	int fs = 0;
	int result = 0;

	int ret = FileOper::fileReader(fn, &buf, &fs);
	if (ret <= 0) {
		return 0;
	}

	int cfglen = Public::removespace(buf, buf);
	char* str = buf;
	int flag = 0;
	char sub[1024];
	char* pos = str;
	int len = 0;
	while (1) {
		char * ptr = strstr(str,CRLN);
		if (ptr > 0) {
			pos = str;

			len = ptr - str;
			memcpy(sub, str, len);
			sub[len] = 0;

			str = ptr + strlen(CRLN);
		}
		else {
			ptr = strstr(str,CRLNLINUX);
			if (ptr > 0) {
				pos = str;
				len = ptr - str;
				memcpy(sub, str, len);
				sub[len] = 0;
				str = ptr + strlen(CRLNLINUX);
			}
			else {
				pos = str;
				len = strlen(str);
				memcpy(sub, str, len);
				sub[len] = 0;
				str = str + len;
				flag = 1;
			}
		}
		if ( ( str[0] == '#') || (str[0]== '/' && str[1] == '/') )
		{
			continue;
		}
		const char* end = 0;
		const char* hdr = 0;
		hdr = strstr(sub, "[");
		if (hdr > 0) {
			hdr += strlen("[");
			end = strstr(hdr, "]");
			if (end > 0 && (end - hdr > 0)) {
				string kv = string(hdr, end - hdr);
				int offset = kv.find("=");
				if (offset != std::string::npos) {
					string k = kv.substr(0, offset);
					string v = kv.substr(offset + 1);
					if (k == key) {
						if (v == value) {
							result = 1;
							break;
						}
						else {
							string s = key + "=" + value;
							string fstr = string(buf, pos) + "\r\n[" +  s + "]\r\n" + string(str);
							FileOper::fileWriter(fn, fstr.c_str(), fstr.length(), 1);
							result = 1;
							break;
						}
					}
				}
			}
		}

		if (flag > 0) {
			break;
		}

		continue;
	}

	if (result == 0)
	{
		char s[1024];
		wsprintfA(s, "\r\n[%s=%s]\r\n", key.c_str(), value.c_str());
		string fstr = string(buf) + s;
		FileOper::fileWriter(fn, fstr.c_str(), fstr.length(),1);
	}
	delete buf;
	
	return result;
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

