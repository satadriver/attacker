
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
		// ���̵�PEB
		mov eax, fs:[30h]
		// ���ƶѲ��������Ĺ�����ʽ�ı�־λ
		mov eax, [eax + 68h]
		// ����ϵͳ�������Щ��־λFLG_HEAP_ENABLE_TAIL_CHECK, 
		// FLG_HEAP_ENABLE_FREE_CHECK and FLG_HEAP_VALIDATE_PARAMETERS��
		// ���ǵĲ�������x70
		// ����Ĵ����൱��C/C++��
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
//����ֱ���û�����س�ʱ������������ַ���ͬ�س�һ�������̻�������
//���������к�̵�getchar();��������ֱ�Ӵӻ����������ȡ��������ַ��������ֱ��������Ϊ��ʱ�����¶�ȡ�û��ļ������롣

//getch
//����һ������������룬���ð��س��ͷ��ء�
//�ú����ķ���ֵ���������ַ���ASCII�룬�Ҹú��������벻���Զ���ʾ����Ļ�ϣ���Ҫputchar();���������ʾ

//putch()����Ļ����ַ��ĺ��� 
//putchar()��stdout������ַ��ĺ� 
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