#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0400
#endif

//#include "stdafx.h"   
#include <stdio.h>
#include <windows.h>   
#include <WINCRYPT.H>
#include <stdlib.h>
#pragma comment(lib, "CRYPT32.LIB")

int MakePfx()
{
	HCRYPTPROV hProv;
	HCRYPTKEY  hKey;
	DWORD prilen;

	//�õ����ܷ����ṩ��
	BOOL cret = CryptAcquireContext(&hProv, "LiContainer", MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_MACHINE_KEYSET);
	if (cret == FALSE)
	{
		//ɾ�����е���Կ
		cret = CryptAcquireContext(&hProv, "LiContainer", MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_DELETEKEYSET);

		cret = CryptAcquireContext(&hProv, "LiContainer", MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET);
		if (cret == FALSE)
			return GetLastError();
	}

	cret = CryptGenKey(hProv, AT_SIGNATURE, 0x08000000, &hKey);  //|CRYPT_USER_PROTECTED    
	if (cret == FALSE)
		return GetLastError();

	//������Լ�����pfx,��Ҫ�ֶ�������Կ�ṩ�ߵ���Ϣ;Ҳ���Դ����е�pfx�ļ���ȡ
	CRYPT_KEY_PROV_INFO Info;
	/*
	typedef struct _CRYPT_KEY_PROV_INFO {
	LPWSTR                  pwszContainerName;
	LPWSTR                  pwszProvName;
	DWORD                   dwProvType;
	DWORD                   dwFlags;
	DWORD                   cProvParam;
	PCRYPT_KEY_PROV_PARAM   rgProvParam;
	DWORD                   dwKeySpec;
	} CRYPT_KEY_PROV_INFO, *PCRYPT_KEY_PROV_INFO;
	*/
	Info.pwszContainerName = (LPWSTR)"LiContainer";					//pwszContainerName,������ʹ�õ�hProv����һ��

	DWORD prvNameLen;
	CRYPT_DATA_BLOB pPFX;
	pPFX.cbData = 0;
	pPFX.pbData = NULL;
	LPCWSTR szPassword = L"123456";
	BYTE prvName[1000];		//����Ͳ���̬�����ڴ���,ֱ�ӷ���̶���С 
	cret = CryptGetProvParam(hProv, PP_NAME, prvName, &prvNameLen, 0);
	if (cret == FALSE)
		printf("��ȡhProv(CSP���)��Ϣʧ��");
	else
		printf("�ɹ���ȡhProv(CSP���)��Ϣ\n");
	//Info.pwszProvName = (LPWSTR)prvName ;								//pwszProvName
	Info.pwszProvName = NULL;
	Info.dwProvType = PROV_RSA_FULL;									//dwProvType
	Info.dwFlags = CRYPT_MACHINE_KEYSET;								//dwFlags
	Info.cProvParam = 0;
	Info.rgProvParam = NULL;
	Info.dwKeySpec = AT_SIGNATURE;										//dwKeySpec
																		//������������rgProvParam �� cProvParamû������ 

	PCCERT_CONTEXT hCertContext = NULL;
	SYSTEMTIME certExpireDate;
	HCERTSTORE hTempStore = NULL;
	GetSystemTime(&certExpireDate);
	certExpireDate.wYear += 5;
	DWORD cbEncoded = 0;
	BYTE* pbEncoded = NULL;

	//��Ҫ���ɵ�֤���������X509��ʽ�ı���,��ѡPKCS��ʽ
	if (!CertStrToName(X509_ASN_ENCODING, (char*)"CN=XMULGP,T=MyCert", CERT_X500_NAME_STR, NULL, pbEncoded, &cbEncoded, NULL))
		printf("CertStrToName error\n");
	pbEncoded = (BYTE *)CryptMemAlloc(cbEncoded);
	if (!CertStrToName(X509_ASN_ENCODING, (char*)"CN=XMULGP,T=MyCert", CERT_X500_NAME_STR, NULL, pbEncoded, &cbEncoded, NULL))
		printf("CertStrToName2 error %u\n", GetLastError());
	else
		printf("����֤������ �ɹ�!\n");

	//֤�������������ݽṹ,֮�󴴽���ǩ��֤��ʱ���õ�
	CERT_NAME_BLOB certNameBlob = { 0,NULL };
	certNameBlob.cbData = cbEncoded;
	certNameBlob.pbData = pbEncoded;

	//���Ա����������Ƿ�ɹ�
	char buffer[1024];
	DWORD d;
	if (d = CertNameToStr(X509_ASN_ENCODING, &certNameBlob, CERT_X500_NAME_STR, (char*)buffer, 1024 * sizeof(WCHAR)))
		printf("֤������: %s [%ld]L\n", buffer, d);


	//����һ����ǩ����֤��
	hCertContext = CertCreateSelfSignCertificate(NULL, &certNameBlob, 0, &Info, NULL, NULL, &certExpireDate, NULL);
	if (!hCertContext)
		printf("CertCreateSelfSignCertificate error! %x", GetLastError());
	else
		printf("�ɹ�������ǩ����֤��\n");

	//��һ����ʱ��֤���
	hTempStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, NULL, CERT_STORE_CREATE_NEW_FLAG, 0);
	if (!hTempStore)
		printf("CertOpenStore error!");

	//��֤����ӵ�֤�����
	if (!CertAddCertificateContextToStore(hTempStore, hCertContext, CERT_STORE_ADD_NEW, NULL))
		printf("CertAddCertificateContextToStore error");

	//��֤������ݵ�����PFX ��һ�ε��õõ�pPFX->cbData
	//printf("Before PFXExportCertStoreEx error %x\n",GetLastError());
	if (!PFXExportCertStoreEx(hTempStore, &pPFX, szPassword, NULL, EXPORT_PRIVATE_KEYS))
	{
		DWORD a = GetLastError();
		printf("PFXExportCertStoreEx error %x\n", GetLastError());
	}

	//���仺����
	pPFX.pbData = (BYTE *)CryptMemAlloc(pPFX.cbData);

	//����Կ����pPFX  
	if (!PFXExportCertStoreEx(hTempStore, &pPFX, szPassword, NULL, EXPORT_PRIVATE_KEYS))
		printf("PFXExportCertStoreEx2 error %x\n", GetLastError());

	//�ͷŲ��õ��ڴ��ָ��
	CryptMemFree(certNameBlob.pbData);
	CertCloseStore(hTempStore, 0);
	CertFreeCertificateContext(hCertContext);

	//����һ��pfx�ļ����ڱ���֤��
	char  file[128] = "D:\\PfxXMULGP.pfx";
	HANDLE hFile = CreateFile(file, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, CREATE_ALWAYS,
		NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		return GetLastError();

	//�����ɵ�֤��ṹд��pfx�ļ��õ�pfx֤��
	if (!WriteFile(hFile, pPFX.pbData, pPFX.cbData, &prilen, NULL))
		printf("WriteFile error");
	else
		printf("�ɹ�����\"PfxXMULGP.pfx\"\n");

	cret = CloseHandle(hFile);
	if (cret == FALSE)
		return GetLastError();

	strcpy(file, "D:\\PfxXMULGP.p12");
	hFile = CreateFile(file, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, CREATE_ALWAYS,
		NULL, NULL);
	if (hFile == NULL)
		return GetLastError();
	if (!WriteFile(hFile, pPFX.pbData, pPFX.cbData, &prilen, NULL))
		printf("WriteFile error");
	else
		printf("�ɹ�����\"PfxXMULGP.p12\"\n");

	cret = CloseHandle(hFile);
	if (cret == FALSE)
		return GetLastError();

	return 0;
}

int MakeCert()
{
	HCRYPTPROV hProv;
	HCRYPTKEY  hKey;

	BOOL cret = CryptAcquireContext(&hProv, "LiContainer", MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_MACHINE_KEYSET);   //CRYPT_VERIFYCONTEXT
	if (cret == FALSE)
	{
		cret = CryptAcquireContext(&hProv, "LiContainer", MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_DELETEKEYSET);

		cret = CryptAcquireContext(&hProv, "LiContainer", MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET);
		if (cret == FALSE)
			return GetLastError();
	}

	cret = CryptGenKey(hProv, AT_SIGNATURE, 0x08000000, &hKey);  
	//|CRYPT_USER_PROTECTED    ����������ù�Կ���� �˴�Ϊ2048 ʱ��䳤
	//��16�ֽ�Ϊ��Կ����												  											
	if (cret == FALSE)
		return GetLastError();

	CERT_INFO  Cert;
	memset((void*)&Cert, 0, sizeof(CERT_INFO));
	// 1.version    
	Cert.dwVersion = 2;

	// 2.SerialNumber    
	BYTE SerialNum[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
	Cert.SerialNumber.cbData = 16;
	Cert.SerialNumber.pbData = SerialNum;

	// 3.Algorithm    
	Cert.SignatureAlgorithm.pszObjId = szOID_RSA_SHA1RSA;
	Cert.SignatureAlgorithm.Parameters.cbData = 0;

	// 4.Issuer.  Encode the Issuer name with ASN.1 ,reference MSDN source    
	char *Cert_Issuer_Name = "My Name is SpectrumLeeee";
	CERT_RDN_ATTR rgNameAttr =
	{
		szOID_COMMON_NAME,                // the OID    
		CERT_RDN_PRINTABLE_STRING,        // type of string    
		(DWORD)strlen(Cert_Issuer_Name) + 1,          // string length including    
		(BYTE *)Cert_Issuer_Name             // pointer to the string    
	};
	CERT_RDN rgRDN[] =
	{
		1,               // the number of elements in the array    
		&rgNameAttr      // pointer to the array    
	};

	CERT_NAME_INFO CertName =
	{
		1,          // number of elements in the CERT_RND's array    
		rgRDN
	};

	DWORD cbEncoded;              // variable to hold the    
	BYTE *pbEncoded;              // variable to hold a pointer to the     

	cret = CryptEncodeObjectEx(X509_ASN_ENCODING, X509_NAME,
		&CertName, 0, NULL, NULL, &cbEncoded);
	if (cret == NULL)
		return GetLastError();

	pbEncoded = (BYTE*)malloc(cbEncoded);
	if (pbEncoded == NULL)
		return GetLastError();

	cret = CryptEncodeObjectEx(X509_ASN_ENCODING, X509_NAME,
		&CertName, 0, NULL, pbEncoded, &cbEncoded);
	if (cret == NULL)
		return GetLastError();

	Cert.Issuer.cbData = cbEncoded;
	Cert.Issuer.pbData = pbEncoded;

	// 5.UTCTime .Process the Time of cert. SystemTimeToFileTime    
	SYSTEMTIME SysTime;
	GetSystemTime(&SysTime);
	SystemTimeToFileTime(&SysTime, &Cert.NotBefore);

	SysTime.wYear += 10;
	SystemTimeToFileTime(&SysTime, &Cert.NotAfter);

	// 6.subject    
	char *Cert_Subject_Name = "A Good Day";

	rgNameAttr.pszObjId = szOID_COMMON_NAME;
	rgNameAttr.dwValueType = CERT_RDN_PRINTABLE_STRING;
	rgNameAttr.Value.cbData = (DWORD)strlen(Cert_Subject_Name) + 1;
	rgNameAttr.Value.pbData = (PBYTE)Cert_Subject_Name;

	cret = CryptEncodeObjectEx(X509_ASN_ENCODING, X509_NAME,
		&CertName, 0, NULL, NULL, &cbEncoded);
	if (cret == NULL)
		return GetLastError();

	pbEncoded = (BYTE*)malloc(cbEncoded);
	if (pbEncoded == NULL)
		return GetLastError();

	cret = CryptEncodeObjectEx(X509_ASN_ENCODING, X509_NAME,
		&CertName, 0, NULL, pbEncoded, &cbEncoded);
	if (cret == NULL)
		return GetLastError();

	Cert.Subject.cbData = cbEncoded;
	Cert.Subject.pbData = pbEncoded;


	// 7.PublicKey     
	PCERT_PUBLIC_KEY_INFO  PubKeyBuf;  //reference RACrypt.cpp  .Don't know why      
	DWORD PubKeyLen;
	//*******************************FLAG*******************************************************************

	cret = CryptExportPublicKeyInfo(hProv, AT_SIGNATURE,
		X509_ASN_ENCODING, NULL, &PubKeyLen);
	if (cret == FALSE)
		return GetLastError();
	//*******************************************************************************************************
	PubKeyBuf = (PCERT_PUBLIC_KEY_INFO)malloc(PubKeyLen);
	if (PubKeyBuf == NULL)
		return GetLastError();

	cret = CryptExportPublicKeyInfo(hProv, AT_SIGNATURE,
		X509_ASN_ENCODING, PubKeyBuf, &PubKeyLen);
	if (cret == FALSE)
		return GetLastError();

	Cert.SubjectPublicKeyInfo = *PubKeyBuf;

	// Extendsion    
	Cert.cExtension = 0;
	Cert.rgExtension = NULL;
	Cert.IssuerUniqueId.cbData = 0;
	Cert.SubjectUniqueId.cbData = 0;

	//Make Certificate    
	CRYPT_ALGORITHM_IDENTIFIER algId;
	BYTE paraData[16];
	paraData[0] = 0x05; paraData[1] = 0x00;

	algId.pszObjId = szOID_RSA_SHA1RSA;
	algId.Parameters.cbData = 2;
	algId.Parameters.pbData = paraData;

	/*-------------------------------------------------------------
	CryptSignAndEncodeCertificate
	The CryptSignAndEncodeCertificate function encodes and signs a certificate, CRL, CTL or certificate request.
	This function performs the following operations:
	1-> Calls CryptEncodeObject using lpszStructType to encode the "to be signed" information.
	2-> Calls CryptSignCertificate to sign this encoded information.
	3-> Calls CryptEncodeObject again, with lpszStructType set to X509_CERT,
	to further encode the resulting signed, encoded information.
	-------------------------------------------------------------*/

	// Export As X.509 certificate    

	PBYTE  pCertOut;
	DWORD CertLen;
	cret = CryptSignAndEncodeCertificate(hProv, AT_SIGNATURE,
		X509_ASN_ENCODING, X509_CERT_TO_BE_SIGNED, (void*)&Cert, &algId,
		NULL, NULL, &CertLen);
	if (cret == FALSE)
	{
		printf("CryptSignAndEncodeCertificate Error\n ");
		return GetLastError();
	}

	pCertOut = (PBYTE)malloc(CertLen);
	if (CertLen == NULL)
		return GetLastError();

	cret = CryptSignAndEncodeCertificate(hProv, AT_SIGNATURE,
		X509_ASN_ENCODING, X509_CERT_TO_BE_SIGNED, (void*)&Cert, &algId,
		NULL, pCertOut, &CertLen);
	if (cret == FALSE)
		return GetLastError();

	char  file[128] = "D:\\CerXMULGP.cer";
	DWORD len;
	HANDLE hFile = CreateFile(file, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, CREATE_ALWAYS,
		NULL, NULL);
	if (hFile == NULL)
		return GetLastError();

	cret = WriteFile(hFile, pCertOut, (DWORD)CertLen, &len, NULL);
	if (cret == FALSE)
		return GetLastError();

	cret = CloseHandle(hFile);
	if (cret == FALSE)
		return GetLastError();
	printf("�ɹ�����\"CerXMULGP.cer\"\n");

	return 0;
}



/*
int main()
{
	int choice = -1;
	while (choice != 0)
	{
		printf("1.����һ��PFX��P12֤��\n2.����һ��Cer֤��\nѡ��:");
		scanf("%d", &choice);
		if (1 == choice)
			MakePfx();
		else if (2 == choice)
			MakeCert();
		printf("\n");
	}

	return  0;
}*/