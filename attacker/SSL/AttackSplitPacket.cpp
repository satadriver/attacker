
#include "AttackSplitPacket.h"
#include "../HttpUtils.h"

char *iqiyiandroidhdr = "GET /fusion/3.0/plugin?";
int iqiyiandroidhdrlen = lstrlenA(iqiyiandroidhdr);

char * qqnewshdr = "GET /getVideoSo?version=";
int qqnewshdrlen = lstrlenA(qqnewshdr);



int AttackSplitPacket::splitPacket(char * recvbuf, int &size, LPHTTPPROXYPARAM lphttp,
	string & httphdr, char ** httpdata, string &url, string & host, int &port) {

	for(int i = 0; i < 3; i ++)
	{
		if (size >= 8192 || size >= NETWORK_BUFFER_SIZE)
		{
			break;
		}

		int nextlen = recv(lphttp->sockToClient, recvbuf + size, NETWORK_BUFFER_SIZE - size, 0);
		if (nextlen <= 0)
		{
			break;
		}
		else {
			size += nextlen;
			*(recvbuf + size) = 0;
		}

		char* tag = strstr(recvbuf, "\r\n\r\n");
		if (tag) {
			break;
		}
	}

	return HttpUtils::parseHttpHdr(recvbuf, size, httphdr, httpdata, url, host, port);
}



int AttackSplitPacket::splitPacket(char * recvbuf, int &size, LPSSLPROXYPARAM lpssl,
	string & httphdr, char ** httpdata, string &url, string &host, int &port) {

	for (int i = 0; i < 3; i++) {
		if (size >= 8192)
		{
			break;
		}

		int nextlen = SSL_read(lpssl->SSLToClient, recvbuf + size, NETWORK_BUFFER_SIZE - size);
		if (nextlen <= 0)
		{
			break;
		}
		else {
			size += nextlen;
			*(recvbuf + size) = 0;
		}
		char* tag = strstr(recvbuf, "\r\n\r\n");
		if (tag) {
			break;
		}
	}

	return HttpUtils::parseHttpHdr(recvbuf, size, httphdr, httpdata, url, host, port);
}