

#include "informerclient.h"
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

InformerClient* gInformerClient;


int initIpUser(InformerClient* instance) {
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


InformerClient::InformerClient() {

	if (mInstance)
	{
		return;
	}
	mInstance = this;

	gInformerClient = this;

	int ret = initIpUser(mInstance);

	gIPV4TargetMap.clear();

	InitializeCriticalSection(&mCS);

	DWORD dwThreadid = 0;
	CloseHandle(CreateThread(0, PROXY_THREAD_STACK_SIZE, (LPTHREAD_START_ROUTINE)online,
		this, STACK_SIZE_PARAM_IS_A_RESERVATION, &dwThreadid));
}

InformerClient::~InformerClient() {

}


int InformerClient::storeTarget(string key, string username) {
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
			printf("checkTarget insert key:%s,username:%s error\r\n", key.c_str(), username.c_str());
		}
	}
	else {
		if (it->second == username)
		{
		}
		else {
			it->second = username;
		}
		ret = TRUE;
	}

	LeaveCriticalSection(&mInstance->mCS);
	return ret;
}



string InformerClient::getTarget(unsigned long ip, string host) {

	string strip = HttpUtils::getIPstr(ip);

	string username = getTarget(strip);
	if (username != "")
	{
		return username;
	}

	return getTarget(host);
}



string InformerClient::getTarget(string key) {

	string ret = "";

	int waittimes = (CLIENTIP_WAIT_DELAY) / CLIENTIP_WAIT_SPLITDELAY;

	for (int i = 0; i < waittimes; i++)
	{
		EnterCriticalSection(&gInformerClient->mCS);

		unordered_map <string, string>::iterator it;
		it = gInformerClient->gIPV4TargetMap.find(key);
		if (it != gInformerClient->gIPV4TargetMap.end())
		{
			ret = it->second;
		}

		LeaveCriticalSection(&gInformerClient->mCS);

		if (ret == "")
		{
			Sleep(CLIENTIP_WAIT_SPLITDELAY);
		}
		else {
			break;
		}
	}

	if (ret == "")
	{
		ret = G_USERNAME;
		char szout[1024];
		wsprintfA(szout, "not found username with key:%s,use default username:%s\r\n", key.c_str(), G_USERNAME);
		Public::WriteLogFile(szout);
	}

	return ret;
}





int __stdcall InformerClient::online(InformerClient* instance) {

	try {
		while (1) {
			string path = Public::getpath();
			string filename = path + IPV4_ONLINE_FILENAME;
			int ret = DeleteFileA(filename.c_str());
			time_t now = time(0);
			unordered_map <string, string>::iterator it;
			for (it = instance->gIPV4TargetMap.begin(); it != instance->gIPV4TargetMap.end(); ) {
				char buf[1024];
				int len = wsprintfA(buf, "key:%s,username:%s\r\n", it->first.c_str(), it->second.c_str());

				ret = FileOper::fileWriter(filename, buf, len, FALSE);

				++it;
			}

			Sleep(60000);
		}
	}
	catch (const std::exception& e) {
		printf("SSLTarget online exception:%s\r\n", e.what());
	}
	return 0;
}