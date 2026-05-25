
#include <stdio.h>
#include <Windows.h>
#include <string.h>
#include <string>
#include <memory.h>
#include "compression.h"
#include <conio.h>
#include "utils.h"
#include "FileOper.h"


#pragma comment(lib,"lib/zlib.lib")
#pragma comment(lib,"ws2_32.lib")

using namespace std;

#define DEFAULT_INPUT_FILENAME		"ssl.txt"
#define DEFAULT_OUTPUT_FILENAME		"sslout.txt"



int unzip(char* infile,char* outfile) {

	int ret = 0;

	char* infn = 0;
	if (infile) {
		infn = infile;	
	}
	else {
		infn = (char*)DEFAULT_INPUT_FILENAME;
	}
	HANDLE hfin = CreateFileA(infn, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hfin == INVALID_HANDLE_VALUE) {
		printf("%s %d CreateFileA file:%s error:%d\r\n",__FUNCTION__,__LINE__, infn, GetLastError());
		return -1;
	}

	char* outfn = 0;
	if (outfile) {
		outfn = outfile;
	}
	else if (infile) {
		int fp = -1;
		int sp = -1;
		SplitFileName(infile, &fp, &sp);
		char outfn_new[MAX_PATH] = { 0 };
		int mfnl = sp - fp;
		int offset = 0;
		memcpy(outfn_new+offset,infile+ fp, mfnl);
		offset += mfnl;
		memcpy(outfn_new + offset, "_out", 4);
		offset += 4;
		strcpy(outfn_new + offset, infile + sp);
		outfn = outfn_new;
	}
	else {
		outfn = (char*)DEFAULT_OUTPUT_FILENAME;
	}

	HANDLE hfout = CreateFileA(outfn, GENERIC_READ | GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
	if (hfout == INVALID_HANDLE_VALUE) {
		printf("%s %d CreateFileA file:%s\r\n error:%d\r\n", __FUNCTION__, __LINE__, outfn, GetLastError());
		return -1;
	}


	DWORD fs_high = 0;
	int fs = GetFileSize(hfin, &fs_high);
	char* buf = new char[fs + 16];
	DWORD cnt = 0;
	ret = ReadFile(hfin, buf, fs, &cnt, 0);
	CloseHandle(hfin);
	if (ret == 0) {
		printf("%s %d ReadFile:%s\r\n error:%d\r\n", __FUNCTION__, __LINE__, infn,GetLastError());
		return FALSE;
	}
	buf[fs] = 0;

	int httpTotal = 0;
	int unzipTotal = 0;

	for (char * ptr = buf; ptr < buf + fs;  ) {
		int len = (isHttpPacket(ptr) || isHttpResponse(ptr));
		if (len) {
			char* data = strstr(ptr, "\r\n\r\n");
			if (data == 0) {
				printf("http header no data:\r\n%s\r\n", ptr);
				ptr+=len;
				continue;
			}
			data += 4;
			string httphdr = string(ptr, data - ptr);

			const char* tag = "\r\n\r\n--------------------------------------------------------------------------------\r\n\r\n";
			ret = WriteFile(hfout, tag, lstrlenA(tag), &cnt, 0);
			ret = WriteFile(hfout, ptr, (char*)data - ptr, &cnt, 0);

			httpTotal++;

			char* gzip = strstr((char*)httphdr.c_str(), "Content-Encoding: gzip\r\n");
			if (gzip) {
				string cslen = getValueFromKey(httphdr.c_str(), "Content-Length");
				if (cslen != "") {
					int csl = atoi(cslen.c_str());
					if (csl > 0) {
						ret = unzipWrite(hfout, data, csl);
						if (ret) {
							unzipTotal++;
						}
						else {
							printf("%s %d http header uncompress error:\r\n[%s]\r\n", __FUNCTION__, __LINE__, httphdr.c_str());
						}
						data += csl;
					}
					else if (csl == 0) {

					}
					else {
						printf("http header Content-Length error:\r\n[%s]\r\n", httphdr.c_str());			
					}
				}
				else {
					char* chunked = strstr((char*)httphdr.c_str(), "Transfer-Encoding: chunked\r\n");
					if (chunked) {
						int cslen = 0;
						int strchunklen = getChunkSize(data, &cslen);
						data += strchunklen;

						unsigned long unlen = unzipWrite(hfout, data, cslen);
						if (unlen) {
							unzipTotal++;
						}
						else {
							printf("%s %d http header uncompress error:\r\n[%s]\r\n", __FUNCTION__, __LINE__, httphdr.c_str());
						}
						data += cslen;
					}
					else {
						/*
						string cs = getValueFromKey(httphdr.c_str(), "Content-Length");
						if (cs != "") {
							int cslen = atoi(cs.c_str());
							if (cslen > 0) {
								ret = WriteFile(hfout, data, cslen, &cnt, 0);
							}
						}
						else {
							//printf("gzip http Content-Length error:%s\r\n", httphdr.c_str());
						}
						*/
						const char* lphdr = httphdr.c_str();
						printf("http header no chunked:\r\n[%s]\r\n", httphdr.c_str());

					}
				}
			}
			else {
				string cslen = getValueFromKey(httphdr.c_str(), "Content-Length");
				if (cslen!= "") {
					int csl = atoi(cslen.c_str());
					if (csl > 0) {
						ret = WriteFile(hfout, data, csl, &cnt, 0);
					}
					else if (csl == 0) {

					}
					else {
						printf("%s %d error:\r\n[%s]\r\n", __FUNCTION__, __LINE__, httphdr.c_str());
					}
					data += csl;
				}
				else {
					//printf("http header no Content-Length:\r\n[%s]\r\n", httphdr.c_str());
				}
			}
			ptr = data;
		}
		else {
			ptr++;
		}
	}

	CloseHandle(hfout);

	delete[]buf;

	printf("process http packet:%d,unzip packet:%d\r\n", httpTotal, unzipTotal);

	return 0;
}



int main(int argc, char** argv) {
	int ret = 0;
	WSADATA wsa;
	ret = WSAStartup(0x0202, &wsa);

	char path[MAX_PATH];
	int pathlen = GetModuleFileNameA(0, path,sizeof(path));
	for (int i = pathlen-1; i >= 0 ; i--) {
		if (path[i] == '\\') {
			path[i] = 0;
			break;
		}
	}
	SetCurrentDirectoryA(path);

	int seq = 0;
	for (int seq = 1; seq < argc; seq++) {
		if (lstrcmpA(argv[seq], "--unzip") == 0) {
			if (argc > seq + 2) {
				ret = unzip(argv[seq+1], argv[seq + 2]);
			}
			else if (argc >= seq + 1) {
				ret = unzip(argv[seq + 1], 0);
			}
			else {
				ret = unzip(0, 0);
			}
			return ret;
		}
		else if (lstrcmpiA(argv[seq], "--tv") == 0) {
			char* fn = argv[seq + 1];
			char* file = 0;
			int fs = 0;
			ret = FileOper::fileReader(fn, &file, &fs);
			if (fs) {
				ret = TestVersion(file);
				delete file;
			}
		}
	}

	//printf("Press any key to quit...\r\n");
	//ret = _getch();

	return ret;
}