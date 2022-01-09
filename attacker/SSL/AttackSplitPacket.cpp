
#include "AttackSplitPacket.h"
#include "../HttpUtils.h"

char *iqiyiandroidhdr = "GET /fusion/3.0/plugin?";
int iqiyiandroidhdrlen = lstrlenA(iqiyiandroidhdr);

char * qqnewshdr = "GET /getVideoSo?version=";
int qqnewshdrlen = lstrlenA(qqnewshdr);



int AttackSplitPacket::splitPacket(char * recvbuf, int &icount, LPHTTPPROXYPARAM lphttp,
	string & httphdr, char ** httpdata, string &url, string & host, int &port) {

	for(int i = 0; i < 8; i ++)
	{
		if (icount >= 8192)
		{
			break;
		}

		int nextlen = recv(lphttp->sockToClient, recvbuf + icount, NETWORK_BUFFER_SIZE - icount, 0);
		if (nextlen <= 0)
		{
			break;
		}
		else {
			icount += nextlen;
			*(recvbuf + icount) = 0;
		}
	}

	int type = 0;
	return HttpUtils::parseHttpHdr(recvbuf, icount, type, httphdr, httpdata, url, host, port);
}



int AttackSplitPacket::splitPacket(char * recvbuf, int &icount, LPSSLPROXYPARAM lpssl,
	string & httphdr, char ** httpdata, string &url, string &host, int &port) {

	for (int i = 0; i < 8; i++) {
		if (icount >= 8192)
		{
			break;
		}

		int nextlen = SSL_read(lpssl->SSLToClient, recvbuf + icount, NETWORK_BUFFER_SIZE - icount);
		if (nextlen <= 0)
		{
			break;
		}
		else {
			icount += nextlen;
			*(recvbuf + icount) = 0;
		}
	}

	int type = 0;
	return HttpUtils::parseHttpHdr(recvbuf, icount, type, httphdr, httpdata, url, host, port);
}