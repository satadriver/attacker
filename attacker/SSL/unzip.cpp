

#include <Windows.h>
#include <string.h>
#include <string>
#include <memory.h>

#include "sslPublic.h"
#include "../HttpUtils.h"

#include "../cipher/compression.h"

#pragma comment(lib,"lib/zlib.lib")

using namespace std;





string unzipfilepath = "unzip.txt";


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
				*value = stol(slen,0,16);
			}
			else {

			}

			break;
		}
	}

	return len;
}




int unzip(char * buf,int bufsize) {
	return 0;

	int ret = 0;

	int result = 0;

	DWORD cnt = 0;

	char* httpdata = 0;
	string httphdr = HttpUtils::getHttpHeader(buf, bufsize, &httpdata);
	if (httphdr == "" || httpdata == 0) {
		return 0;
	}
	int ds = bufsize - httphdr.size();	
	if (ds == 0) {
		return 0;
	}

	string te = HttpUtils::getValueFromKey(httphdr.c_str(), "Transfer-Encoding");
	if (strstr(te.c_str(), "chunked")) {

		unsigned char* data = (unsigned char*)httpdata;
		int totalsize = 0;
		do {
			int cslen = 0;
			int chunklen = getChunkSize((char*)data, &cslen);
			data += chunklen;

			totalsize += cslen;

			if (totalsize <= ds) {
				if (memcmp(data, "\x1f\x8b\x08\x00", 4) == 0) {
					DWORD unziplen = cslen << 6;
					unsigned char* unzipbuf = new unsigned char[unziplen];
					if (unzipbuf) {
						ret = Compress::gzdecompress(data + 10, cslen - 10, unzipbuf, &unziplen);
						if (ret == 0) {
							string path = gLocalPath + "output\\" + unzipfilepath;
							HANDLE hfout = CreateFileA(path.c_str(), GENERIC_WRITE, 0, 0, OPEN_ALWAYS, 0, 0);
							if (hfout == INVALID_HANDLE_VALUE) {
								return 0;
							}

							const char* tag =
								"\r\n\r\n--------------------------------------------------------------------------------\r\n\r\n";
							ret = WriteFile(hfout, tag, lstrlenA(tag), &cnt, 0);

							ret = WriteFile(hfout, httphdr.c_str(), httphdr.length(), &cnt, 0);
							ret = WriteFile(hfout, unzipbuf, unziplen, &cnt, 0);

							CloseHandle(hfout);

							result = 1;
						}
						delete[] unzipbuf;

						data += cslen;
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

		} while (1);
	}
	else {
		string ce = HttpUtils::getValueFromKey(httphdr.c_str(), "Content-Encoding");
		if (strstr(ce.c_str(), "gzip") == 0 ) {
			return 0;
		}
		string strcs = HttpUtils::getValueFromKey(httphdr.c_str(), "Content-Length");
		int cs = atoi(strcs.c_str());
		if ( cs != ds) {
			return 0;
		}

		unsigned char* data =(unsigned char*) httpdata;
		if (memcmp(data, "\x1f\x8b\x08\x00", 4) == 0) {
			DWORD unziplen = ds << 5;
			unsigned char* unzipbuf = new unsigned char[unziplen];
			if (unzipbuf) {
				ret = Compress::gzdecompress(data + 10, ds - 10, unzipbuf, &unziplen);
				if (ret == 0) {
					string path = gLocalPath + "output\\" + unzipfilepath ;
					HANDLE hfout = CreateFileA(path.c_str(), GENERIC_WRITE, 0, 0, OPEN_ALWAYS, 0, 0);
					if (hfout == INVALID_HANDLE_VALUE) {
						printf("CreateFileA:%s error:%d\r\n", path.c_str(), GetLastError());
						return 0;
					}
					ret = WriteFile(hfout, "\r\n\r\n", 4, &cnt, 0);

						const char* tag =
							"\r\n\r\n--------------------------------------------------------------------------------\r\n\r\n";
						ret = WriteFile(hfout, tag, lstrlenA(tag), &cnt, 0);
					
						ret = WriteFile(hfout, httphdr.c_str(), httphdr.length(), &cnt, 0);
					ret = WriteFile(hfout, unzipbuf, unziplen, &cnt, 0);

					CloseHandle(hfout);

					result = 1;
				}
			}
			delete[] unzipbuf;
		}
	}

	return result;
}

