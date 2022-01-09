
#include "momo.h"
#include "../FileOper.h"
#include "../HttpUtils.h"
#include "PluginServer.h"


int Momo::isMomoDns(string url, string host) {
	if (host == "referee.immomo.com")
	{
		if (strstr(url.c_str(), "/config?version="))
		{

			return TRUE;

		}
	}

	return FALSE;
	
}

int Momo::makeMomoDns(char*recvBuffer, int len, int buflimit, LPHTTPPROXYPARAM lphttp) {

	string fn = Public::getUserPluginPath(lphttp->username) + "momodns.txt";
	char * lpdata = 0;
	int filesize = 0;
	int ret = FileOper::fileReader(fn, &lpdata, &filesize);
	if (ret <= 0)
	{
		return FALSE;
	}

	string serverip = HttpUtils::getIPstr(gServerIP);
	string fc = lpdata;

// 	int start = 0;
// 	while (1)
// 	{
// 		
// 		string flag = "\"host\":\"";
// 
// 		start = fc.find(flag,start);
// 		if (start >= 0)
// 		{
// 			start += flag.length();
// 			int end = fc.find("\"",start);
// 			if (end >= 0)
// 			{
// 				fc = fc.replace(start, end - start, serverip);
// 				start = end;
// 			}
// 			else {
// 				break;
// 			}
// 		}
// 		else {
// 			break;
// 		}
// 	}
// 
// 	start = 0;
// 	while (1)
// 	{
// 		string flag = "this is replaced ip";
// 
// 		start = fc.find(flag,start);
// 		if (start >= 0)
// 		{
// 			fc = fc.replace(start,flag.length() , serverip);
// 			start += flag.length();
// 		}
// 		else {
// 			break;
// 		}
// 	}

	char * szHttpRespFormat = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: application/json\r\nContent-Length: %u\r\n\r\n%s";

	int resultlen = sprintf(recvBuffer, szHttpRespFormat, fc.length(), fc.c_str());
	return resultlen;

}