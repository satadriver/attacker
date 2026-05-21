
#include <windows.h>
#include "ImportCert.h"
#include <string.h> //MFC-only string objects
#include <shlobj.h>
#include <atlstr.h> //Non-MFC string objects
#include <sal.h>
#include "Cryptuiapi.h"
#include <iostream>
#include "sslPublic.h"
#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <string>



#pragma  comment(lib,"Cryptui.lib")
#pragma comment(lib,"Crypt32.lib")

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




int ImportRootCertification(unsigned char * certificateData,int certSize) {
	// 1. 准备证书数据（示例数据，需替换为实际证书的字节流）
	// 实际使用时，应从证书文件（如 .cer, .crt）中读取字节到该数组中。
	// 例如： vector<BYTE> certData = ReadCertificateFile("path/to/your/certificate.cer");
	//const BYTE certificateData[1024] = { /* 证书的二进制数据 */ };
	//DWORD certSize = sizeof(certificateData);

	// 2. 打开 "ROOT" 系统存储
	HCERTSTORE hRootStore = CertOpenSystemStoreW(NULL, L"ROOT");
	if (!hRootStore) {
		std::cerr << "打开根证书存储失败。错误码: " << GetLastError() << std::endl;
		return 1;
	}

	// 3. 从原始数据创建证书上下文
	PCCERT_CONTEXT pCertContext = CertCreateCertificateContext(
		X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		certificateData,
		certSize
	);

	if (!pCertContext) {
		std::cerr << "创建证书上下文失败。错误码: " << GetLastError() << std::endl;
		CertCloseStore(hRootStore, 0);
		return 1;
	}

	// 4. 将证书添加到根存储
	if (!CertAddCertificateContextToStore(
		hRootStore,
		pCertContext,
		CERT_STORE_ADD_REPLACE_EXISTING, // 如果存在则替换
		NULL
	)) {
		std::cerr << "添加证书到存储失败。错误码: " << GetLastError() << std::endl;
		CertFreeCertificateContext(pCertContext);
		CertCloseStore(hRootStore, 0);
		return 1;
	}

	std::cout << "证书成功导入到受信任的根证书颁发机构！" << std::endl;

	// 5. 清理资源
	CertFreeCertificateContext(pCertContext);
	CertCloseStore(hRootStore, 0);

	return 0;
}



//certmgr -add D:\\BaiduNetdiskDownload\\HttpsMidInMan\\HttpsMidInMan\\work\\httpsca.crt -s -r localMachine AuthRoot
int ImportCert::ImportCACertification(int tag) {

	int ret = 0;
	if ((tag & 2) == 0 ) {
		return 0;
	}

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

	flag = 0;
	do
	{
		flag = CryptUIWizImport(CRYPTUI_WIZ_NO_UI, NULL, NULL, &importSrc, NULL);
		Sleep(1000);
		CString strErr;
		strErr.Format(_T("证书导入失败 0x%x\n"), GetLastError());
		
	} while (flag == 0);

	return TRUE;
}