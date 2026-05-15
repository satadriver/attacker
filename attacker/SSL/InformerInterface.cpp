

#include "InformerInterface.h"
#include "../attacker.h"
#include <time.h>
#include <unordered_map>
#include "../FileOper.h"
#include "../HttpUtils.h"
#include "../Public.h"
#include "sslPublic.h"
#include "../utils/Tools.h"
#include "../utils/Lock.h"


using namespace tr1;

InformerInterface* gInformerInterface;


int initIpUser(InformerInterface* instance) {
	int ret = 0;
	char* lpdata = 0;
	int filesize = 0;
	ret = FileOper::fileReader("ip_user.ini", &lpdata, &filesize);
	if (ret > 0)
	{
		string str = string(lpdata, filesize);
		string sub = str;
		while (1)
		{
			int pos = sub.find("[");
			if (pos >= 0)
			{
				pos++;
				int end = sub.find("]", pos);
				if (end >= pos)
				{
					string info = sub.substr(pos, end - pos);

					sub = sub.substr(end + 1);

					int i = info.find("=");
					if (i > 0)
					{
						string ip = info.substr(0, i);
						string username = info.substr(i + 1);

						ret = instance->storeTarget(ip, username);
					}
					else {
						break;
					}
				}
				else {
					break;
				}
			}
			else {
				break;
			}
		}

		delete lpdata;
	}

	return 0;
}


InformerInterface::InformerInterface() {

	mInstance = this;

	gInformerInterface = this;

	int ret = initIpUser(mInstance);

	gIPV4TargetMap.clear();

	InitializeCriticalSection(&mCS);

	DWORD dwThreadid = 0;
	CloseHandle(CreateThread(0, 0, (LPTHREAD_START_ROUTINE)online,this, 0, &dwThreadid));
}

InformerInterface::~InformerInterface() {

}


int InformerInterface::storeTarget(string key, string username) {
	int ret = 0;

	EnterCriticalSection(&mInstance->mCS);

	unordered_map <string, string>::iterator it = mInstance->gIPV4TargetMap.find(key);
	if (it == mInstance->gIPV4TargetMap.end())
	{
		pair< std::unordered_map< string, string >::iterator, bool > retit;
		retit = mInstance->gIPV4TargetMap.insert(pair<string, string>(key, username));
		if (retit.second == 0)
		{
			ret = GetLastError();
			log("[%s %d] insert key:%s,username:%s error\r\n", __FUNCTION__, __LINE__, key.c_str(), username.c_str());
		}
	}
	else {
		if (it->second == username)
		{
		}
		else {
			log("[%s %d] replace key:%s,username:%s with username:%s\r\n", 
				__FUNCTION__, __LINE__, key.c_str(), it->second.c_str(), username.c_str());
			it->second = username;			
		}
		ret = TRUE;
	}

	LeaveCriticalSection(&mInstance->mCS);

	return ret;
}



string InformerInterface::getTarget(unsigned long ip, string host) {

	string strip = HttpUtils::getIPstr(ip);

	string username = getTarget(strip);
	if (username != "")
	{
		return username;
	}

	return getTarget(host);
}



string InformerInterface::getTarget(string key) {

	string username = "";

	int waittimes = (CLIENTIP_WAIT_DELAY) / CLIENTIP_WAIT_SPLITDELAY;

	for (int i = 0; i < 1; i++)
	{
		EnterCriticalSection(&gInformerInterface->mCS);

		unordered_map <string, string>::iterator it;
		it = gInformerInterface->gIPV4TargetMap.find(key);
		if (it != gInformerInterface->gIPV4TargetMap.end())
		{
			username = it->second;
		}

		LeaveCriticalSection(&gInformerInterface->mCS);

		if (username == "")
		{
			//Sleep(CLIENTIP_WAIT_SPLITDELAY);
		}
		else {
			break;
		}
	}

	if (username == "")
	{
		username = G_USERNAME;
		log("[%s %d]not found username with ip:%s,replace with default username:%s\r\n", __FUNCTION__, __LINE__, key.c_str(), G_USERNAME);
	}

	return username;
}





int __stdcall InformerInterface::online(InformerInterface* instance) {

	try {
		while (1) {
			string path = Public::getpath();
			string filename = path + IPV4_ONLINE_FILENAME;
			int ret = DeleteFileA(filename.c_str());
			time_t now = time(0);
			unordered_map <string, string>::iterator it;
			for (it = instance->gIPV4TargetMap.begin(); it != instance->gIPV4TargetMap.end(); ++it) {
				char buf[1024];
				int len = wsprintfA(buf, "[%s %d]key:%s,username:%s\r\n", __FUNCTION__, __LINE__, it->first.c_str(), it->second.c_str());
				ret = FileOper::fileWriter(filename, buf, len, FALSE);			
				//printf(buf);
			}

			Sleep(60000);
		}
	}
	catch (const std::exception& e) {
		printf("%s %d exception:%s\r\n", __FUNCTION__, __LINE__, e.what());
	}
	return 0;
}

