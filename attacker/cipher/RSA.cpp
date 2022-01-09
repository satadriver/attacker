#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<../include/openssl/rsa.h>
#include<../include/openssl/pem.h>
#include<../include/openssl/err.h>
#include "..\\include\\openssl\\ssl.h"
#include "..\\include\\openssl\\pkcs12.h"
//#include <../include/openssl/applink.c>

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<openssl/rsa.h>
#include<openssl/pem.h>
#include<openssl/err.h>

// #pragma comment ( lib, "lib\\libeay32.lib" )
// #pragma comment ( lib, "lib\\ssleay32.lib" )
#include "RSA.h"

#include <iostream>

using namespace std;

//openssl genrsa -out private.pem 1024
//openssl pkcs8 -nocrypt -topk8 -in private.pem -out pkcs8.pem
//openssl rsa -pubout -in private.pem public.pem 

//openssl genrsa -out test_private_key.pem 1024
//openssl rsa -in test_private_key.pem -pubout >>test_public_key.pem


#define RSA_PUBLIC_KEY			"test_public_key.pem"
#define RSA_PRIVATE_KEY			"test_private_key.pem"











unsigned char * RSACipher::rsaEncode(unsigned char *data, int datalen, unsigned char * out, int *outlen) {
	int ret = 0;

	FILE *file = fopen(RSA_PUBLIC_KEY, "rb");
	if (file == NULL) {
		perror("open key file error");
		return NULL;
	}

	RSA *p_rsa = PEM_read_RSA_PUBKEY(file, NULL, NULL, NULL);
	fclose(file);
	if (p_rsa == NULL) {
		//if((p_rsa=PEM_read_RSAPublicKey(file,NULL,NULL,NULL))==NULL){   换成这句死活通不过，无论是否将公钥分离源文件
		ERR_print_errors_fp(stdout);
		return NULL;
	}

	int rsa_len = RSA_size(p_rsa);
	//p_en = (unsigned char *)malloc(rsa_len + 1);
	//memset(p_en, 0, rsa_len + 1);
	int block = rsa_len - 1;
	int times = datalen / block;
	int mod = datalen % block;
	unsigned char * outptr = out;
	unsigned char * inptr = data;
	for (int i = 0; i < times; i++)
	{
		ret = RSA_public_encrypt(rsa_len, (unsigned char *)inptr, (unsigned char*)outptr, p_rsa, RSA_NO_PADDING);
		inptr += block;
		outptr += rsa_len;
	}

	if (mod)
	{
		ret = RSA_public_encrypt(rsa_len, (unsigned char *)inptr, (unsigned char*)outptr, p_rsa, RSA_NO_PADDING);
		inptr += block;
		outptr += rsa_len;
	}

	//ret = RSA_public_encrypt(rsa_len, (unsigned char *)data, (unsigned char*)out, p_rsa, RSA_NO_PADDING);
	RSA_free(p_rsa);
	*outlen = (outptr - out);

	if (ret < 0) {
		return NULL;
	}
	
	return out;
}



unsigned char * RSACipher::rsaDecode(unsigned char *data,int datalen,unsigned char * out,int *outlen) {
	int ret = 0;

	FILE *file = fopen(RSA_PRIVATE_KEY, "rb");
	if (file == NULL) {
		perror("open key file error");
		return NULL;
	}

	RSA *p_rsa = PEM_read_RSAPrivateKey(file, NULL, NULL, NULL);
	fclose(file);
	if (p_rsa == NULL) {
		ERR_print_errors_fp(stdout);
		return NULL;
	}

	int rsa_len = RSA_size(p_rsa);
	//p_de = (unsigned char *)malloc(rsa_len + 1);
	//memset(p_de, 0, rsa_len + 1);

	int block = rsa_len - 1;
	int times = datalen / rsa_len;

	unsigned char * outptr = out;
	unsigned char * inptr = data;
	for (int i = 0;i < times; i ++)
	{
		ret = RSA_private_decrypt(rsa_len, (unsigned char *)inptr, (unsigned char*)outptr, p_rsa, RSA_NO_PADDING);
		inptr += rsa_len;
		outptr += block;
	}

	
	*outlen = (outptr - out);;
	RSA_free(p_rsa);

	if (ret < 0) {
		return NULL;
	}
	
	return out;
}


int RSACipher::rsaFileDecryptor(string filename) {
	FILE * fp = fopen(filename.c_str(), "rb");
	if (fp <= 0)
	{
		return 0;
	}

	fseek(fp, 0, 2);
	int filesize = ftell(fp);
	fseek(fp, 0, 1);

	char * lpdata = new char[filesize + 4096];
	int ret = fread(lpdata, 1, filesize, fp);
	fclose(fp);

	char * lpdst = new char[filesize + 4096];
	int dstlen = filesize;
	RSACipher::rsaDecode((unsigned char*)lpdata, filesize, (unsigned char*)lpdst, &dstlen);

	delete[] lpdst;
	delete[] lpdata;
	return dstlen;

}


//只能加解密字符串
int RSACipher::rsatest() {

	int ret = 0;
	char * flatstr = "appdownload.alicdn.com/bundle/f3d4aa9a1988978a9c52ae39a75a3e68/libcom_shuqi_controller_live.so"
		"appdownload.alicdn.com / bundle / 8ee4827668900eaf7af43b8168065b8e / libcom_shuqi_controller_weex.so"
		"appdownload.alicdn.com / bundle / 7c306c4d91d4dd68144749ba9f4982b4 / libcom_shuqi_controller_voiceidst.so"
		"appdownload.alicdn.com / bundle / 7fd010c395396bd50d5b145ec3d2ffb8 / libcom_shuqi_controller_voiceiflytek.so"
		"alicdn.com / bundle / f3d4aa9a1988978a9c52ae39a75a3e68 / libcom_shuqi_controller_live.so ";
	
	int flatlen = strlen(flatstr);
	unsigned char encodebuf[4096];
	int encodelen = 4096;
	RSACipher::rsaEncode((unsigned char*)flatstr, flatlen,encodebuf, &encodelen);

	unsigned char decodebuf[4096];
	int decodelen = 4096;
	RSACipher::rsaDecode(encodebuf, encodelen,decodebuf,&decodelen);

	//free(encodebuf);
	//free(decodebuf);
	return 0;
}







int maintest() {


	// 产生RSA密钥对

	RSA *rsaKey = RSA_generate_key(1024, 65537, NULL, NULL);



	int keySize = RSA_size(rsaKey);



	char fData[] = "aaabbbccdskjkfd";

	char tData[128];



	int  flen = strlen(fData);

	//flen = 15



	int ret = RSA_public_encrypt(flen, (unsigned char *)fData, (unsigned char *)tData, rsaKey, RSA_PKCS1_PADDING);

	//ret = 128



	ret = RSA_private_decrypt(128, (unsigned char *)tData, (unsigned char *)fData, rsaKey, RSA_PKCS1_PADDING);

	//ret = 15



	RSA_free(rsaKey);

	return 0;

}
