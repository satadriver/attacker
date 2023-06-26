
#include <windows.h>
#include "ImportCert.h"
#include <string.h> //MFC-only string objects
#include <shlobj.h>
#include <atlstr.h> //Non-MFC string objects
#include <sal.h>
#include "Cryptuiapi.h"
#include <iostream>
#include "sslPublic.h"


#include <string>

#pragma  comment(lib,"Cryptui.lib")

using namespace std;



int __stdcall findAndConsentImportCert(int * flag) {
	int ret = 0;

	string cap = "安全警告";
	HWND hwnd = FindWindowA(0, cap.c_str());
	while (hwnd == NULL  )
	{
		if (*flag == FALSE)
		{
			hwnd = FindWindowA(0, cap.c_str());
			Sleep(20);
		}
		else {
			return TRUE;
		}
	}

	char szclsname[MAX_PATH] = { 0 };
	ret = GetClassNameA(hwnd, szclsname, MAX_PATH);
	//if (ret && strstr(szclsname,"#32770"))
	//{
		ret = SetForegroundWindow(hwnd);

		keybd_event('Y', 0, 0, 0);
		keybd_event('Y', 0, KEYEVENTF_KEYUP, 0);
		return TRUE;
	//}
	//else {
	//	return FALSE;
	//}

}

//cert8.db
//certutil -addstore root d:\server.crt







//certmgr -add D:\\BaiduNetdiskDownload\\HttpsMidInMan\\HttpsMidInMan\\work\\httpsca.crt -s -r localMachine AuthRoot
int ImportCert::ImportCACertification() {

	int ret = 0;

	string cacrtfn = gLocalPath + CA_CERT_PATH + "\\"+ CA_CRT_FILENAME;
	char szcmdfmt[] = "certutil -addstore root %s";
	char szcmd[1024];
	ret = wsprintfA(szcmd, szcmdfmt, cacrtfn.c_str());
	system(szcmd);
	//ret = WinExec(szcmd,SW_HIDE);
	return TRUE;


	WCHAR path[1024];
	int len =MultiByteToWideChar(CP_ACP,0,cacrtfn.c_str(),cacrtfn.length(),path,MAX_PATH);
	*(DWORD*)(path + len) = 0;

	CRYPTUI_WIZ_IMPORT_SRC_INFO importSrc = { 0 };
	importSrc.dwSize = sizeof(CRYPTUI_WIZ_IMPORT_SRC_INFO);
	importSrc.dwSubjectChoice = CRYPTUI_WIZ_IMPORT_SUBJECT_FILE;
	importSrc.pwszFileName = path;
	importSrc.dwFlags = CRYPT_EXPORTABLE | CRYPT_USER_PROTECTED | CRYPTUI_WIZ_IMPORT_TO_LOCALMACHINE;

	int flag = FALSE;
	CloseHandle(CreateThread(0, 0, (LPTHREAD_START_ROUTINE)findAndConsentImportCert, &flag, 0, 0));
	//Sleep(1000);

	flag = CryptUIWizImport(CRYPTUI_WIZ_NO_UI, NULL, NULL, &importSrc, NULL);
	while (flag == 0)
	{
		Sleep(6000);
		CString strErr;
		strErr.Format(_T("证书导入失败 0x%x\n"), GetLastError());
		//MessageBox(NULL, strErr, NULL, 0);
		//return FALSE;

		flag = CryptUIWizImport(CRYPTUI_WIZ_NO_UI, NULL, NULL, &importSrc, NULL);
	}

	return TRUE;
}