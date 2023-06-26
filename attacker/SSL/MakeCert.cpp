

#include "MakeCert.h"
#include "sslPublic.h"
#include "../attacker.h"
#include <io.h>


//带括号的是正版 https://blog.csdn.net/oldmtn/article/details/52208747


//(openssl x509 -req -in ca/ca-req.csr -out ca/ca-cert.pem -signkey ca/ca-key.pem -days 3650)
int MakeCert::makeCRTSelf(string csrfn, string password, string certfn, string cakeyfn) {

	char* signcmdformat = "openssl x509 -req -days 3650 -passin pass:%s -in %s -signkey %s -out %s";
	char szcmd[1024];
	int len = wsprintfA(szcmd, signcmdformat, password.c_str(), csrfn.c_str(), cakeyfn.c_str(), certfn.c_str());

	int ret = system(szcmd);
	if (ret)
	{
		printf("makeCRTSelf error:%u\r\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}




//命令行创建crt，并用父证书签名
//(openssl x509 -req -in server/server-req.csr -out server/server-cert.pem -signkey server/server-key.pem -CA ca/ca-cert.pem 
//-CAkey ca/ca-key.pem -CAcreateserial -days 3650 )

//openssl x509 -req -in subcacsr.csr -out subcacrt.crt -passin pass:12345678 -signkey subca.key -CA cacrt.crt -CAkey cakey.key -CAcreateserial -days 3650
int MakeCert::makeCRT(string csrfn, string password, string subcakey, string cacertfn, string certfn, string cakeyfn) {

	char* signcmdformat = "openssl x509 -req -in %s -passin pass:%s -signkey %s -CA %s -CAkey %s -CAcreateserial -out %s -extensions v3_ca -days 3650";
	char szcmd[1024];
	int len = wsprintfA(szcmd, signcmdformat, csrfn.c_str(), password.c_str(), subcakey.c_str(), cacertfn.c_str(), cakeyfn.c_str(), certfn.c_str());

	int ret = system(szcmd);
	if (ret)
	{
		printf("makeCRT error:%u\r\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}







//命令行创建csr
//openssl req -new -key cakey.key -passin pass:12345678 
//-subj /C=zn/ST=zhejiang/L=hangzhou/O=gxt/OU=dev/CN=com.qq.mail/emailAddress=email -extensions v3_ca -out subcsr.csr -days 3650

//(openssl req -new -out server/server-req.csr -key server/server-key.pem)
int MakeCert::makeCSR(string keyfn, string password, string c, string st, string l, string o, string ou, string cn, string e, string outcsrfn) {
	char* cmdformat =
		"openssl req -new -key %s "\
		"-passin pass:%s "\
		"-subj /C=%s/ST=%s/L=%s/O=%s/OU=%s/CN=%s/emailAddress=%s "\
		"-extensions v3_ca -out %s -days 3650";

	char szcmd[1024];
	int len = wsprintfA(szcmd, cmdformat, keyfn.c_str(), password.c_str(),
		c.c_str(), st.c_str(), l.c_str(), o.c_str(), ou.c_str(), cn.c_str(), e.c_str(), outcsrfn.c_str());

	int ret = system(szcmd);
	if (ret)
	{
		printf("makeCSR error:%u\r\n", GetLastError());
		return FALSE;
	}
	return TRUE;
}





//openssl ca -in app.csr -out app.crt -cert CA.crt -keyfile CA.key -days 1826 -policy policy_anything
int MakeCert::makeSuperCRT(string csrfn, string password, string cacertfn, string certfn, string cakeyfn) {

	char* signcmdformat = "openssl ca -extensions v3_ca -passin pass:%s -in %s -out %s -cert %s -keyfile %s -days 3650 -policy policy_anything -batch";
	char szcmd[1024];
	int len = wsprintfA(szcmd, signcmdformat, password.c_str(), csrfn.c_str(), certfn.c_str(), cacertfn.c_str(), cakeyfn.c_str());

	int ret = system(szcmd);
	if (ret)
	{
		printf("makeSuperCRT error:%u\r\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}


//passout代替shell进行密码输入否则会提示输入密码
int MakeCert::makeKey(string password, string keypath, int bitcnt) {
	char* cmdformat = "openssl genrsa -passout pass:%s -out \"%s\" %u";
	char cmd[1024];
	int len = wsprintfA(cmd, cmdformat, password.c_str(), keypath.c_str(), bitcnt);
	int ret = system(cmd);
	if (ret)
	{
		printf("makeKey error:%u\r\n", GetLastError());
		return FALSE;
	}
	return TRUE;
}

//openssl req -new -x509 -days 5480 -subj /C=US/ST=California/O=GeoAuth\ Inc./CN=Authentication\ Global\ Root -keyout CA.key -out CA.crt
int MakeCert::makeSuperCACRT(string keyfn, string password,
	string c, string st, string l, string o, string ou, string cn, string e, string outcrtfn) {
	char* cmdformat =
		"openssl req -new -x509 -days 3650 -keyout \"%s\" "\
		"-passout pass:%s "\
		"-subj /C=%s/ST=%s/L=%s/O=%s/OU=%s/CN=%s/emailAddress=%s "\
		"-extensions v3_ca "		//v3-ca is for version v1 v2 v3 
		"-out \"%s\"";

	char szcmd[1024];
	int len = wsprintfA(szcmd, cmdformat, keyfn.c_str(), password.c_str(),
		c.c_str(), st.c_str(), l.c_str(), o.c_str(), ou.c_str(), cn.c_str(), e.c_str(), outcrtfn.c_str());

	int ret = system(szcmd);
	if (ret)
	{
		printf("makSupereCACRT error:%u\r\n", GetLastError());
		return FALSE;
	}

	char passwordprotect[] = "openssl rsa -in \"%s\" -out \"%s\" -passin pass:%s";
	len = wsprintfA(szcmd, passwordprotect, keyfn.c_str(), keyfn.c_str(), password.c_str());
	ret = system(szcmd);
	if (ret)
	{
		printf("makSupereCACRT remove password protect error:%u\r\n", GetLastError());
		return FALSE;
	}
	return TRUE;
}




//openssl req -new -sha256 -key server.key -subj "/C=CN/ST=GD/L=SZ/O=lee/OU=study/CN=bdstatic.com" 
//-reqexts SAN -config c:\openssl\bin\openssl.cfg -out server.csr
int MakeCert::makeExtCSR(string keyfn, string password, string c, string st, string l, string o, string ou, string cn, string e, string cfgpath, string outcsrfn) {
	char* cmdformat =
		"openssl req -new -key \"%s\" "\
		"-passin pass:%s "\
		"-subj /C=%s/ST=%s/L=%s/O=%s/OU=%s/CN=%s/emailAddress=%s "\
		"-extensions v3_ca "
		"-reqexts SAN -config \"%s\" "
		"-out \"%s\" -days 3650";

	char szcmd[1024];
	int len = wsprintfA(szcmd, cmdformat, keyfn.c_str(), password.c_str(),
		c.c_str(), st.c_str(), l.c_str(), o.c_str(), ou.c_str(), cn.c_str(), e.c_str(), cfgpath.c_str(), outcsrfn.c_str());

	int ret = system(szcmd);
	if (ret)
	{
		printf("makeCSR:%s error:%u\r\n", szcmd, GetLastError());
		return FALSE;
	}
	return TRUE;
}


//v3_ca
//openssl ca -in server.csr -md sha256 -keyfile ca.key -cert ca.crt -extensions SAN -config c:\openssl\bin\openssl.cfg -out server.crt
int MakeCert::makeExtCRT(string cfgpath, string csrfn, string password, string cacertfn, string certfn, string cakeyfn) {

	char* signcmdformat = "openssl ca -extensions SAN -config \"%s\" -passin pass:%s -in \"%s\" -out \"%s\" -cert \"%s\" -keyfile \"%s\" "\
		"-days 3650 -policy policy_anything -batch";
	char szcmd[1024];
	int len = wsprintfA(szcmd, signcmdformat, cfgpath.c_str(), password.c_str(), csrfn.c_str(), certfn.c_str(), cacertfn.c_str(), cakeyfn.c_str());

	int ret = system(szcmd);
	if (ret)
	{
		printf("makeSuperCRT error:%u\r\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}








/*
根证书的操作步骤
1 创建密钥
openssl genrsa -des3 -out httpsca.key 1024
2 创建csr
openssl req -new -key httpsca.key -out httpsca.csr
3 自己给自己签名生成证书
openssl x509 -req -in httpsca.csr -out httpsca.crt -signkey httpsca.key -days 3650
*/
int MakeCert::makeCA(string cacsrpath, string cacrtpath, string cakeypath) {

	int ret = 0;

	string subcsrkey = gLocalPath + CA_CERT_PATH + "\\" + SUBCA_KEY_FILENAME;
	ret = makeKey(PRIVATE_KEY_PWD, subcsrkey, MAKE_KEY_LEN);
	if (ret == FALSE)
	{
		printf("make sub ca key error\r\n");
		MessageBoxA(0, "make sub ca key error", "make sub ca key error", MB_OK);
		exit(0);
	}

#ifdef DEBUG_MAKE_CERT_V3
	string cfgpath = gOpensslPath + OPENSSLCONFIG_FILENAME;
	ret = makeSuperCACRT(cakeypath, string(PRIVATE_KEY_PWD),
		ROOT_CERT_C, ROOT_CERT_ST, ROOT_CERT_L, ROOT_CERT_O, ROOT_CERT_OU, ROOT_CERT_CN, ROOT_CERT_E, cfgpath, cacrtpath);
	if (ret == FALSE)
	{
		printf("ca makSupereCACSR error\r\n");
		MessageBoxA(0, "ca makSupereCACSR error", "ca makSupereCACSR error", MB_OK);
		exit(0);
	}
#elif defined DEBUG_MAKE_CERT_V3_EXT
	string cfgpath = gOpensslPath + OPENSSLCONFIG_FILENAME;
	ret = makeSuperCACRT(cakeypath, string(PRIVATE_KEY_PWD),
		ROOT_CERT_C, ROOT_CERT_ST, ROOT_CERT_L, ROOT_CERT_O, ROOT_CERT_OU, ROOT_CERT_CN, ROOT_CERT_E, cacrtpath);
	if (ret == FALSE)
	{
		printf("ca makSupereCACSR error\r\n");
		MessageBoxA(0, "ca makSupereCACSR error", "ca makSupereCACSR error", MB_OK);
		exit(0);
	}
#else
	ret = makeKey(PRIVATE_KEY_PWD, cakeypath, MAKE_KEY_LEN);
	if (ret == FALSE)
	{
		printf("ca makekey error\r\n");
		exit(0);
	}

	ret = makeCSR(cakeypath, string(PRIVATE_KEY_PWD), ROOT_CERT_C, ROOT_CERT_ST, ROOT_CERT_L, ROOT_CERT_O, ROOT_CERT_OU, ROOT_CERT_CN, ROOT_CERT_E, cacsrpath);
	if (ret == FALSE)
	{
		printf("ca makeCSR error\r\n");
		exit(0);
	}

	ret = makeCRTSelf(cacsrpath, PRIVATE_KEY_PWD, cacrtpath, cakeypath);
	if (ret == FALSE)
	{
		printf("ca makeCRT error\r\n");
		exit(0);
	}
#endif

	return TRUE;
}



int MakeCert::checkCAExist() {
	string cakeypath = gLocalPath + CA_CERT_PATH + "\\" + CA_KEY_FILENAME;
	string subcakeypath = gLocalPath + CA_CERT_PATH + "\\" + SUBCA_KEY_FILENAME;
	string cacsrpath = gLocalPath + CA_CERT_PATH + "\\" + CA_CSR_FILENAME;
	string cacrtpath = gLocalPath + CA_CERT_PATH + "\\" + CA_CRT_FILENAME;

	HANDLE hf = CreateFileA(cakeypath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hf == INVALID_HANDLE_VALUE)
	{
		return makeCA(cacsrpath, cacrtpath, cakeypath);
	}
	else {
		CloseHandle(hf);
	}

	hf = CreateFileA(subcakeypath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hf == INVALID_HANDLE_VALUE)
	{
		return makeCA(cacsrpath, cacrtpath, cakeypath);
	}
	else {
		CloseHandle(hf);
	}

	hf = CreateFileA(cacrtpath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hf == INVALID_HANDLE_VALUE)
	{
		return makeCA(cacsrpath, cacrtpath, cakeypath);
	}
	else {
		CloseHandle(hf);
	}

	return TRUE;
}



//域名得层级是倒叙的
//.COM 商业机构
//网络提供商的.net 
//表示非盈利组织的.org

int MakeCert::MakesureCertExist(string servername) {
	int ret = 0;
	if (servername == "")
	{
		return FALSE;
		servername = "localhost.com";
	}
	string crtfn = gLocalPath + CERT_PATH + "\\" + servername + ".crt";
	string outcsrfn = gLocalPath + CERT_PATH + "\\" + servername + ".csr";

	string subkeyfn = gLocalPath + CA_CERT_PATH + "\\" + SUBCA_KEY_FILENAME;

	string cakeyfn = gLocalPath + CA_CERT_PATH + "\\" + CA_KEY_FILENAME;

	//string cacsrfn = gLocalPath + CA_CERT_PATH + "\\" + CA_CSR_FILENAME;

	string cacrtfn = gLocalPath + CA_CERT_PATH + "\\" + CA_CRT_FILENAME;

	string password = string(PRIVATE_KEY_PWD);

	HANDLE hfcrt = CreateFileA(crtfn.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hfcrt != INVALID_HANDLE_VALUE) {
		int crtfs = GetFileSize(hfcrt, 0);
		CloseHandle(hfcrt);
		if (crtfs > 0)
		{
			return TRUE;
		}
		else {
			ret = DeleteFileA(crtfn.c_str());
		}
	}

	string cfgsrcfile = gOpensslPath + OPENSSLCONFIG_FILENAME;
	string cfgpath = gOpensslPath + OPENSSLCONFIG_FILENAME + "_" + servername;
	ret = CopyFileA(cfgsrcfile.c_str(), cfgpath.c_str(), 0);
	if (ret == 0)
	{
		printf("copy openssl config file from:%s to:%s error code:%u\r\n", cfgsrcfile.c_str(), cfgpath.c_str(), GetLastError());
		return FALSE;
	}

	//multi dns format:
	//"\n[ SAN ]\nsubjectAltName=DNS:qq1.com\n"
	//"\n[ SAN ]\nsubjectAltName=DNS:qq2.com\n"
	//"\n[ SAN ]\nsubjectAltName=DNS:qq3.com\n"


//#define __CERT_IMPORT_TEST
#ifdef _DEBUG
#ifdef __CERT_IMPORT_TEST
	char* dns = (char*)servername.c_str();
	int dnslen = servername.length();
	int flag = 0;
	for (int i = dnslen - 1; i >= 0; i--)
	{
		if (dns[i] == '.')
		{
			flag++;
			if (flag == 2)
			{
				dns[i] = '0';
				flag = 0;
				break;
			}
		}
	}
#endif
#endif

#define SUBJECT_NAME_LIMIT 1024
	char szout[1024];
	char szbuf[SUBJECT_NAME_LIMIT];
	int altnamelen = wsprintfA(szbuf, "\n[ SAN ]\nsubjectAltName=DNS:%s\n", servername.c_str());
	HANDLE hfcfg = CreateFileA(cfgpath.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hfcfg == INVALID_HANDLE_VALUE)
	{
		printf("CreateFileA openssl config file:%s,error code:%u\r\n", cfgpath.c_str(), GetLastError());
		return FALSE;
	}
	ret = SetFilePointer(hfcfg, 0, 0, FILE_END);
	DWORD dwcnt = 0;
	ret = WriteFile(hfcfg, szbuf, altnamelen, &dwcnt, 0);
	ret = FlushFileBuffers(hfcfg);
	CloseHandle(hfcfg);
	if (ret == FALSE)
	{
		printf("WriteFile openssl config file:%s,error code:%u\r\n", szbuf, GetLastError());
		return FALSE;
	}

	//nRetCode = makeCSR(subkeyfn, password, 
	//	ROOT_CERT_C, ROOT_CERT_ST, ROOT_CERT_L, ROOT_CERT_O, ROOT_CERT_OU, servername, ROOT_CERT_E,  outcsrfn);
	ret = DeleteFileA(outcsrfn.c_str());
	ret = MakeCert::makeExtCSR(subkeyfn, password,
		ROOT_CERT_C, ROOT_CERT_ST, ROOT_CERT_L, ROOT_CERT_O, ROOT_CERT_OU, servername.c_str(), ROOT_CERT_E, cfgpath, outcsrfn);
	if (ret == FALSE)
	{
		int outlen = wsprintfA(szout, "makeExtCSR:%s error code:%u\r\n", servername.c_str(), GetLastError());
		Public::WriteLogFile(ATTACK_LOG_FILENAME, szout, outlen);
		return FALSE;
	}

	ret = MakeCert::makeExtCRT(cfgpath, outcsrfn, password, cacrtfn, crtfn, cakeyfn);
	if (ret == FALSE)
	{
		int outlen = wsprintfA(szout, "makeExtCRT:%s error code:%u\r\n", servername.c_str(), GetLastError());
		Public::WriteLogFile(ATTACK_LOG_FILENAME, szout, outlen);
		return FALSE;
	}

	ret = DeleteFileA(cfgpath.c_str());
	ret = DeleteFileA(outcsrfn.c_str());

	return TRUE;
}
