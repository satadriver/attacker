
#include "security.h"
#include <windows.h>
#include <stdio.h>
#include <iostream>
#include "attacker.h"
#include<stdlib.h>
#include <conio.h>

using namespace std;

int  Security::isDebuggered ()
{
	return IsDebuggerPresent();
#ifndef _WIN64
	int result = 0;
	__asm
	{
		// 进程的PEB
		mov eax, fs:[30h]
		// 控制堆操作函数的工作方式的标志位
		mov eax, [eax + 68h]
		// 操作系统会加上这些标志位FLG_HEAP_ENABLE_TAIL_CHECK, 
		// FLG_HEAP_ENABLE_FREE_CHECK and FLG_HEAP_VALIDATE_PARAMETERS，
		// 它们的并集就是x70
		// 下面的代码相当于C/C++的
		// eax = eax & 0x70
		and eax, 0x70
		mov result, eax
	}

	return result != 0;
#else
	return IsDebuggerPresent();
#endif
}


int __stdcall Security::antiDebug() {
	while (1)
	{
		if (isDebuggered())
		{
			MessageBoxA(0, "debuggered", "debuggered", MB_OK);
			ExitProcess(0);
		}

		Sleep(3000);
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
int Security::loginCheck(int mode,string &struser,string &strpass) {

	char szuser[1024] = { 0 };
	if (struser == "")
	{
		printf("please input username:");

		scanf("%s", szuser);
	}
	else {
		lstrcpyA(szuser, struser.c_str());
	}

	char szpw[1024] = { 0 };
	if (strpass == "")
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
			else {
				szpw[cnt] = c;
				cnt++;
				putchar('*');
			}

		} while (c != '\r');

		//scanf("%s", szpw);
		printf("\r\n");
	}
	else {
		lstrcpyA(szpw, strpass.c_str());
	}
	
	string password = "123456";

	if (lstrcmpiA(szpw, password.c_str()))
	{
		return FALSE;
	}

	if (mode == 1 || mode == 3 )
	{
		if (lstrcmpiA(szuser, G_USERNAME))
		{
			return FALSE;
		}
	}else if (mode == 2)
	{
		if (lstrcmpiA(szuser, SERVER_USERNAME))
		{
			return FALSE;
		}
	}
	else {
		return FALSE;
	}

	struser = szuser;
	strpass = password;
	return TRUE;
}