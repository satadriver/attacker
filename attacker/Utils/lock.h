#pragma once

#include <windows.h>

#pragma pack(1)
//typedef struct{} ֻ�Ƕ��� struct{}�Զ�����һ���ṹ��
typedef struct
{
	char name[16];
	int flag;
	ULONGLONG id;
	int timelimit;
}TOOLSLOCK, *LPTOOLSLOCK;
#pragma pack()

#ifndef TOOLS_H_H_H
#define TOOLS_H_H_H

#include <windows.h>
#include <iostream>

using namespace std;




class Lock {
public:
	static int initlock(TOOLSLOCK &, const char *, int timelimit);
	static volatile int enterlock(TOOLSLOCK &, ULONGLONG);
	static volatile int leavelock(TOOLSLOCK &, ULONGLONG);
};

#endif