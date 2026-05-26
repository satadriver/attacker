
#include "safeGuard.h"
#include <windows.h>
#include <stdio.h>
#include <iostream>
#include "attacker.h"
#include<stdlib.h>
#include <conio.h>
#include "main.h"
#include "cipher/CryptoUtils.h"
#include "Config.h"
#include "Utils/Tools.h"

using namespace std;

int  SafeGuard::isDebuggered ()
{
	return IsDebuggerPresent();
#ifndef _WIN64
	int result = 0;
	__asm
	{
		// 进程的PEB
		mov eax, fs:[30h]
		mov eax, [eax + 68h]
		// 操作系统会加上这些标志位FLG_HEAP_ENABLE_TAIL_CHECK,  FLG_HEAP_ENABLE_FREE_CHECK and FLG_HEAP_VALIDATE_PARAMETERS， 它们的并集就是x70
		and eax, 0x70
		mov result, eax
	}

	return result != 0;
#else
	return IsDebuggerPresent();
#endif
}


int __stdcall SafeGuard::antiDebug() {
	while (1)
	{
		if (isDebuggered())
		{
			MessageBoxA(0, "debuggered", "debuggered", MB_OK);
			ExitProcess(0);
		}

		Sleep(1000);
	}
}


//getchar
//函数直到用户输入回车时结束，输入的字符连同回车一起存入键盘缓冲区。
//若程序中有后继的getchar();函数，则直接从缓冲区逐个读取已输入的字符并输出，直到缓冲区为空时才重新读取用户的键盘输入。

//getch
//接受一个任意键的输入，不用按回车就返回。
//该函数的返回值是所输入字符的ASCII码，且该函数的输入不会自动显示在屏幕上，需要putchar();函数输出显示

//putch()向屏幕输出字符的函数 
//putchar()在stdout上输出字符的宏 

char* g_username = "un_test";
char* g_password = "pw_0123456789";
char* g_pwsalt = "this is a test";
char* g_unsalt = "this is a test";
char* g_macsalt = "this is a test";

string GetUserPassFromStr(string src) {
	string str = src;

	int pos = str.find(":");
	if (pos != std::string::npos) {
		str = str.substr(pos + 1);
	}
	else {
		pos = str.find("_");
		if (pos == std::string::npos) {
			log("%s %d code checksum error\r\n", __FUNCTION__, __LINE__);
			ExitProcess(0);
		}
		str = str.substr(pos + 1);
	}
	return str;
}


int SafeGuard::signCheck(string  tag,string user,string pass,string sign) {

	int ret = 0;
	char md5[64] = { 0 };

	char str[256];
	lstrcpyA(str, tag.c_str());
	lstrcatA(str, user.c_str());
	lstrcatA(str, pass.c_str());
	lstrcatA(str, g_macsalt);
	CryptoUtils::getDataMd5((char*)str, strlen(str), md5, 1);
	if (md5 == sign) {
		ret = TRUE;
	}
	if (sign == "") {
		Config::reviseConfig(CONFIG_FILENAME, "sign", md5);
		ret = TRUE;
	}
	if (ret == 0) {
		exit(0);
	}
	return ret;
}


int SafeGuard::loginCheck(int mode,string user,string pass) {

	string password = GetUserPassFromStr( g_password);
	string username = GetUserPassFromStr(g_username);

	lstrcpyA(G_USERNAME, username.c_str());

	if (mode == ATTACK_TEST_MODE || mode == ATTACK_CLIENT_MODE || mode == ATTACK_STANDBY_MODE)
	{
		return TRUE;
	}

	char usermd5[256] = { 0 };
	if (user == "")
	{
		char un[256];
		printf("please input username:");
		int cnt = scanf("%s", un);
		printf("\r\n");
		lstrcatA(un, g_unsalt);
		CryptoUtils::getDataMd5(un, strlen(un), usermd5, 1);
	}
	else {
		lstrcpyA(usermd5, user.c_str());
	}

	char pwmd5[256];
	char pw[256] = { 0 };
	if (pass == "")
	{
		printf("please input password:");

		int cnt = 0;
		char c = 0;
		do
		{
			c = _getch();
			if (c == '\r')
			{
				break;
			}
			else if (c == '\b') {
				pw[--cnt] = 0;
				putchar('*');
			}
			else {
				pw[cnt++] = c;
				putchar('*');
			}
		} while (c != '\r');
		lstrcatA(pw, g_pwsalt);
		printf("\r\n");
		CryptoUtils::getDataMd5(pw, strlen(pw), pwmd5, 1);
	}
	else {
		//CryptoUtils::getDataMd5((char*)strpass.c_str(), strpass.length(), szmd5, 1);
		strcpy(pwmd5, pass.c_str());
	}

	char srcpw[256];
	lstrcpyA(srcpw, password.c_str());
	lstrcatA(srcpw, g_pwsalt);
	char passmd5[64];
	CryptoUtils::getDataMd5((char*)srcpw, strlen(srcpw), passmd5, 1);

	char unmd5[64];
	char srcun[256];
	lstrcpyA(srcun, username.c_str());	
	lstrcatA(srcun, g_unsalt);
	CryptoUtils::getDataMd5((char*)srcun, strlen(srcun), unmd5, 1);

	if (lstrcmpiA(passmd5, pwmd5) || lstrcmpiA(usermd5, unmd5))
	{
		log("username or password error\r\n");
		exit(0);
		ExitProcess(0);
		return FALSE;
	}

	if (pass == "")
	{
		Config::reviseConfig(CONFIG_FILENAME, "password", passmd5);
	}

	if (user == "")
	{
		Config::reviseConfig(CONFIG_FILENAME, "username", usermd5);
	}

	return TRUE;
}