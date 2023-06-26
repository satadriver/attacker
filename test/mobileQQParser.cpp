
#include "mobileQQParser.h"
#include "winsock2.h"
#include "qqcrypt.h"
#include "Public.h"
#include "attack.h"

int MobileQQParser::parsePacket(const char * data, int &len,int dport,int sport) {

	const char * packet = data;

	while (packet < data + len)
	{
 		int leastlen = len - (packet - data);

		int packlen = ntohl(*(int*)packet);
		if (packlen > leastlen )
		{
			printf("parsed block size:%u,recved size:%u\r\n", packlen, len);
			return 1;
		}else if (packlen <= 0)
		{
			
			return -2;
		}

		const char * qqdata = packet;

		LPMOBILEQQ_PACK_HDR hdr = (LPMOBILEQQ_PACK_HDR)qqdata;


// 		int bserver = 0;
// 		if (sport == 8080 || sport == 443 || sport == 80 || sport == 14000)
// 		{
// 			bserver = TRUE;
// 		}

		int offset = ntohl(hdr->offset);
		if (offset >= packlen || offset < 0)
		{
			offset = 4;
		}

		qqdata = qqdata + sizeof(MOBILEQQ_PACK_HDR) + offset;

		string qqno = "";
		char qqnolen = *qqdata - sizeof(int);
		qqdata++;
		if (qqnolen >= 5 && qqnolen <= 10)
		{
			qqno = string(qqdata, qqnolen);
			//int qq = atoi(qqno.c_str());
		}
		else if(qqnolen >= 0 && qqnolen < 5){
			qqno = "";
		}
		else {
			printf("error qq no len\r\n");
			return -2;
		}

		qqdata += qqnolen;

		if (hdr->cryption == 2)
		{
			unsigned char key[16] = { 0 };
			unsigned char decodebuf[0x10000];
			int decodelen = 0x10000;
			int cryptlen = packlen - (qqdata - packet);
			int ret = qq_decrypt((unsigned char*)qqdata, cryptlen, key, decodebuf, &decodelen);
			if (/*ret && */decodelen > 0)
			{
				*(decodebuf + decodelen) = 0;
				printf("succeed decrypted size:%u,encrypted size:%u\r\n", decodelen, cryptlen);
				Public::WriteLogFile("mobileqq.dat", (const char*)decodebuf, decodelen);
			}
			else {
				printf("error:decrypted size:%u,encrypted size:%u\r\n", decodelen, cryptlen);
				//printf("decrypt mobile qq fix crypt packet error\r\n");
				return -1;
			}
		}
		else if(hdr->cryption == 0){
			//printf("no cryption mobile qq packet\r\n");
		}
		else if (hdr->cryption == 1)
		{

		}
		else {
			printf("error qq packet cryption\r\n");
			return -1;
		}

		packet += packlen;
	}

	return 0;
}


int MobileQQParser::isMobileQQPack(const char * data, int len,int dport,int sport) {

	if (dport == 8080 || sport == 8080 || dport == 443 || dport == 80 || sport == 443 || sport == 80 || sport == 14000 || sport == 14000)
	{
		//int packlen = ntohl(*(int*)data);
		//if ((packlen == len || packlen < len) && len > 32 && len < MTU)
		//{
			char crypt = *(data + 8);
			if (/*crypt == 1 ||*/ crypt == 2 /*|| crypt == 0*/)
			{
				int ver = *(int*)(data + sizeof(int));
				//°æ±¾ºÅ 3 = 2010 11 = 2016
				if (ver == 0x0a000000 || ver == 0x0b000000 || ver == 0x09000000  || ver == 0x03000000)
				{
					return TRUE;
				}
			}
		//}
	}

	return FALSE;
}






