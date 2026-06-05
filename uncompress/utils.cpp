
#include "utils.h"

#include <string>
#include <Windows.h>
#include "compression.h"
#include "FileOper.h"

using namespace std;

int isHttpResponse(const char* lpdata) {

	if (memcmp(lpdata, "HTTP/1.1 ", 9) == 0 || memcmp(lpdata, "HTTP/1.0 ", 9) == 0) {
		return 9;
	}
	return FALSE;

}

string SplitHttpPacket(const char* data, int len, char** lphttpdata) {

	char* lphdr = strstr((char*)data, "\r\n\r\n");
	if (lphdr == FALSE)
	{
		*lphttpdata = 0;
		return string(data);
	}

	lphdr += 4;
	string httphdr = string(data, lphdr - data);
	*lphttpdata = lphdr;
	return httphdr;
}


int isHttpPacket(const char* lpdata) {

	//HTTP 1.0
	if (memcmp(lpdata, "POST ", 5) == 0) {
		return 5;
	}
	else if (memcmp(lpdata, "GET ", 4) == 0)
	{
		return 4;
	}
	else if (memcmp(lpdata, "HEAD ", 5) == 0)
	{
		return 5;
	}
	//HTTP 1.1
	else if (memcmp(lpdata, "PUT ", 4) == 0)
	{
		return 4;
	}
	else if (memcmp(lpdata, "CONNECT ", 8) == 0)
	{
		return 8;
	}
	else if (memcmp(lpdata, "OPTIONS ", 8) == 0)
	{
		return 8;
	}
	else if (memcmp(lpdata, "DELETE ", 7) == 0)
	{
		return 7;
	}
	else if (memcmp(lpdata, "TRACE ", 6) == 0)
	{
		return 6;
	}

	return FALSE;
}


string getValueFromKey(const char* lphttphdr, string  searchkey) {

	string key = "\r\n" + searchkey + ": ";
	char* phdr = strstr((char*)lphttphdr, key.c_str());
	if (phdr)
	{
		phdr += key.length();
		char* pend = strstr(phdr, "\r\n");
		if (pend)
		{
			int len = pend - phdr;
			if (len > 0 && len < 256) {
				string value = string(phdr, len);
				return value;
			}
		}
	}

	return "";
}



int getChunkSize(char* data, int* value) {
	char slen[16] = { 0 };
	int len = 0;
	for (int j = 0; j < sizeof(slen); j++) {
		if (isalnum(data[j])) {
			slen[j] = data[j];
		}
		else {
			if (data[j] == '\r' && data[j + 1] == '\n') {
				len = j + 2;
				*value = stol(slen, 0, 16);
			}
			else {

			}

			break;
		}
	}

	return len;
}




int getZipType(string httphdr, char* httpdata, char* gz, int* gzsize) {
	char* chunked = strstr((char*)httphdr.c_str(), "Transfer-Encoding: chunked\r\n");
	if (chunked) {

		int cslen = 0;
		int chunklen = getChunkSize(httpdata, &cslen);
		httpdata += chunklen;

		if (cslen > 0) {
			gz = httpdata;
			*gzsize = cslen;
			return 1;
		}
	}
	else {
		string cs = getValueFromKey(httphdr.c_str(), "Content-Length");
		int cslen = atoi(cs.c_str());
		if (cslen > 0) {
			char* gzip = strstr((char*)httphdr.c_str(), "Content-Encoding: gzip\r\n");
			if (gzip) {
				gz = httpdata;
				*gzsize = cslen;
				return 2;
			}
		}
	}
	return 0;
}


int unzipWrite(HANDLE hfout, char* data, int size) {
	int ret = 0;
	DWORD unziplen = size << 6;
	unsigned char* unzipbuf = new unsigned char[unziplen];
	int result = 0;
	if (unzipbuf) {
		if (memcmp(data, "\x1f\x8b\x08", 3) == 0) {
			int offset = 10;
			char flag = data[3];
			if (flag & 4) {
				unsigned short fextra = *(WORD*)(data + offset);
				offset += 2;
			}
			if (flag & 8) {
				while (data[offset++]) {

				}
			}
			if (flag & 0x10) {
				while (data[offset++]) {

				}
			}
			if (flag & 2) {
				unsigned short crc = *(WORD*)(data + offset);
				offset += 2;
			}
			ret = Compress::gzdecompress((unsigned char*)data + offset, size - offset, unzipbuf, &unziplen);
		}

		DWORD cnt = 0;
		if (ret == 0) {
			ret = WriteFile(hfout, unzipbuf, unziplen, &cnt, 0);
			result = unziplen;
		}
		else {
			printf("unzip http:%s size:%d error:%d\r\n", data, size,ret);
		}

		delete[] unzipbuf;
	}

	return result;
}


int TestVersion(char * packet,int len) {

	int ret = 0;

	char* httpdata = 0;
	string httphdr = SplitHttpPacket(packet, len, &httpdata);
	int httpdatalen = 0;
	if(httpdata)
		httpdatalen=strlen(httpdata);

	string host = getValueFromKey(httphdr.c_str(), "Host");

	hostent* pHostent = gethostbyname(host.c_str());
	if (pHostent == 0)
	{
		printf("host:%s can not be resolved\r\n", host.c_str());
		return 0;
	}
	ULONG  pPIp = *(DWORD*)((CHAR*)pHostent + sizeof(hostent) - sizeof(DWORD_PTR));
	ULONG  pIp = *(ULONG*)pPIp;
	DWORD dwip = *(DWORD*)pIp;

	int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0)
	{
		printf("socket error\r\n");
		return -1;
	}

	sockaddr_in sa = { 0 };
	sa.sin_addr.s_addr = dwip;
	sa.sin_family = AF_INET;
	sa.sin_port = ntohs(80);

	ret = connect(sock, (sockaddr*)&sa, sizeof(sockaddr_in));
	if (ret < 0)
	{
		printf("connect error\r\n");
		closesocket(sock);
		return -1;
	}

	int sendlen = send(sock, packet, len, 0);
	if (sendlen <= 0) {
		printf("send error\r\n");
		closesocket(sock);
		return -1;
	}

	int recvbufsize = 0x100000;
	char *recvbuf =new char[recvbufsize];
	int recvlen = recv(sock, recvbuf,recvbufsize,0);
	closesocket(sock);

	if (recvlen <= 0)
	{	
		printf("recv error\r\n");
		return -1;
	}
	
	recvbuf[recvlen] = 0;
	printf("recv packet data:\r\n%s", recvbuf);

	FileOper::fileWriter("version_out.txt", recvbuf, recvlen,1);
	return 0;
}


int SplitFileName(char* fn,int * filepos,int *surfix_pos) {
	int len = strlen(fn);
	*filepos = -1;
	for (int i = len - 1; i >= 0; i--) {
		if (fn[i] == '\\' || fn[i] == '/') {
			if (*filepos == -1) {
				*filepos = i;
			}	
		}
		else if (fn[i] == '.') {
			*surfix_pos = i;
		}
	}
	if(*filepos == -1)
		*filepos = 0;
	return 0;
}


int isAscIP(string ip) {
	if (ip.length() >= 16) {
		return 0;
	}
	int len = 0;
	int num = 0;
	char str[16];
	int prev_pos = 0;
	for (DWORD j = 0; j < ip.length(); j++)
	{
		char c = ip.at(j);
		if (c >= '0' && c <= '9')
		{
			str[len++] = c;
			if (len > 3) {
				return FALSE;
			}
			continue;
		}
		else if (c == '.') {
			num++;
			if (j == 0 || (prev_pos - j == 1)) {
				return FALSE;
			}
			if (len >= 3 && str[0] > '2') {
				return FALSE;
			}
			else if (len >= 3 && str[0] == '2' && str[1] >= '6') {
				return FALSE;
			}
			else if (len >= 3 && str[0] == '2' && str[1] == '5' && str[2] >= '6') {
				return FALSE;
			}
			len = 0;

			prev_pos = j;
		}
		else {
			return FALSE;
		}
	}

	if (num != 3) {
		return FALSE;
	}
	return TRUE;
}