

#include <windows.h>
#include "../include\\zlib.h"
#include "../include\\zconf.h"
#include "compression.h"
#include "../FileOper.h"
#include "../Public.h"

/* Compress data */
int Compress::zcompress(Bytef *data, uLong ndata, Bytef *zdata, uLong *nzdata)
{
	z_stream c_stream;
	int err = 0;

	if(data && ndata > 0)
	{
		c_stream.zalloc = (alloc_func)0;
		c_stream.zfree = (free_func)0;
		c_stream.opaque = (voidpf)0;
		if(deflateInit(&c_stream, Z_DEFAULT_COMPRESSION) != Z_OK) 
			return -1;
		c_stream.next_in  = data;
		c_stream.avail_in  = ndata;
		c_stream.next_out = zdata;
		c_stream.avail_out  = *nzdata;
		while (c_stream.avail_in != 0 && c_stream.total_out < *nzdata) 
		{
			if(deflate(&c_stream, Z_NO_FLUSH) != Z_OK) 
				return -1;
		}
		if(c_stream.avail_in != 0) 
			return c_stream.avail_in;
		for (;;) {
			if((err = deflate(&c_stream, Z_FINISH)) == Z_STREAM_END) 
				break;
			if(err != Z_OK) 
				return -1;
		}
		if(deflateEnd(&c_stream) != Z_OK) 
			return -1;
		*nzdata = c_stream.total_out;
		return 0;
	}
	return -1;
}

/* Uncompress data */
int Compress::zdecompress(Byte *zdata, uLong nzdata,Byte *data, uLong *ndata)
{
	int err = 0;
	z_stream d_stream; /* decompression stream */

	d_stream.zalloc = (alloc_func)0;
	d_stream.zfree = (free_func)0;
	d_stream.opaque = (voidpf)0;
	d_stream.next_in  = zdata;
	d_stream.avail_in = 0;
	d_stream.next_out = data;
	if(inflateInit(&d_stream) != Z_OK) 
		return -1;
	while (d_stream.total_out < *ndata && d_stream.total_in < nzdata) {
		d_stream.avail_in = d_stream.avail_out = 1; /* force small buffers */
		if((err = inflate(&d_stream, Z_NO_FLUSH)) == Z_STREAM_END) 
			break;
		if(err != Z_OK) 
			return -1;
	}
	if(inflateEnd(&d_stream) != Z_OK) 
		return -1;
	*ndata = d_stream.total_out;
	return 0;
}




//GZIP格式标志 1f8b

//CM 压缩方法(0-7 reserved, 8 = deflate)

//FLG（1 byte）：标志位。    
//bit 0 set: FTEXT 文件可能是ASCII文本文件 
//bit 1 set: FHCRC 附加多个gzip文件部分 
//bit 2 set: FEXTRA 存在有可选的附加 内容 
//bit 3 set: FNAME 提供了原始的文件名称 
//bit 4 set: FCOMMENT 则提供有一个O－终结的文件内容 
//bit 5 set: 文件被加密 
//bit 6,7:   保留 

//MTIME（4 byte）：文件更改时间(Unix时间)

//XFL（1 byte）：附加的标志，决定了压缩方法。当CM = 8时，XFL = 2 – 最大压缩但最慢的算法；XFL = 4 – 最快但最小压缩的算法

//OS（1 byte）：这个标志指明了进行压缩时系统的类型。
//0 – FAT filesystem (MS-DOS, OS/2, NT/Win32) 
//1 – Amiga 
//2 – VMS (or OpenVMS) 
//3 – Unix 
//4 – VM/CMS 
//5 – Atari TOS 
//6 – HPFS filesystem (OS/2, NT) 
//7 – Macintosh 
//8 – Z-System 
//9 – CP/M 
//10 – TOPS-20 
//11 – NTFS filesystem (NT) 
//12 – QDOS 
//13 – Acorn RISCOS 
//255 – unknown 

//头部扩展字段,按照顺序依次是：FEXTRA+FNAME+FCOMMENT+FHCRC，不一定都会存在，但是只要存在，不论存在几个，一定要按照顺序来

//DATA

//CRC32（4 byte）：这个是未压缩数据的循环冗余校验值。
//ISIZE（4 byte）：这是原始数据的长度以2的32次方为模的值。GZIP中字节排列顺序是LSB方式，即Little - Endian，与ZLIB中的相反。

int Compress::gzfiledata(Byte *data, uLong ndata, Byte *gzdata, uLong *ngzdata) {
	DWORD crc = crc32(0, data, ndata);

	int ret = 0;

	memcpy(gzdata, "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03", 10);

	DWORD gzsize = *ngzdata - 18;

	ret = Compress::gzcompress(data, ndata, gzdata + 10, &gzsize);
	memcpy(gzdata + 10 + gzsize, &crc, 4);
	memcpy(gzdata + 10 + gzsize + 4, &ndata, 4);
	
	*ngzdata = gzsize + 18;

	return gzsize + 18;
}


int Compress::gzfile(string srcfn, string dstfn,int withname,string ingzfn) {
	int ret = 0;

	//string filename = Public::getNameFromFullPath(dstfn);
	
	unsigned char * data = 0;
	DWORD ndata = 0;

	ret = FileOper::fileDecryptReader(srcfn,(char**) &data, (int*)&ndata);
	if (ret <= 0)
	{
		return FALSE;
	}

	DWORD crc = crc32(0, data, ndata);

	int ngzdata = ndata + 0x1000;
	unsigned char * gzdata = new unsigned char[ngzdata];

	int gzhdrsize = 10;
	if (withname)
	{
		memcpy(gzdata, "\x1f\x8b\x08\x08\x00\x00\x00\x00\x00\x00", gzhdrsize);

		memcpy(gzdata + gzhdrsize, ingzfn.c_str(), ingzfn.length() + 1);

		gzhdrsize += (ingzfn.length() + 1);
	}
	else {
		memcpy(gzdata, "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x00", gzhdrsize);
	}

	DWORD gzsize = ngzdata - gzhdrsize - 8;

	ret = Compress::gzcompress(data, ndata, gzdata + gzhdrsize, &gzsize);
	if (ret < 0)
	{
		delete gzdata;
		return FALSE;
	}

	memcpy(gzdata + gzhdrsize + gzsize, &crc, 4);

	memcpy(gzdata + gzhdrsize + gzsize + 4, &ndata, 4);

	ret = FileOper::fileWriter(dstfn, (char*)gzdata, gzhdrsize + gzsize + 8, 1);

	delete gzdata;

	return gzsize + gzhdrsize + 8;
}


/* Compress gzip data */
int Compress::gzcompress(Bytef *data, uLong ndata, Bytef *zdata, uLong *nzdata)
{
	z_stream c_stream;
	int err = 0;

	if(data && ndata > 0)
	{
		c_stream.zalloc = (alloc_func)0;
		c_stream.zfree = (free_func)0;
		c_stream.opaque = (voidpf)0;
		if (deflateInit2(&c_stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED,-MAX_WBITS, 8, Z_DEFAULT_STRATEGY) != Z_OK) 

		//只有设置为MAX_WBITS + 16才能在在压缩文本中带header和trailer

		//if (deflateInit2(&c_stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED,MAX_WBITS + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK)
		{
			return -1;
		}
			
		c_stream.next_in  = data;
		c_stream.avail_in  = ndata;
		c_stream.next_out = zdata;
		c_stream.avail_out  = *nzdata;
		while (c_stream.avail_in != 0 && c_stream.total_out < *nzdata) 
		{
			if (deflate(&c_stream, Z_NO_FLUSH) != Z_OK)
			{
				return -1;
			}
		}

		if (c_stream.avail_in != 0)
		{
			return c_stream.avail_in;
		}

		for (;;) {
			if ((err = deflate(&c_stream, Z_FINISH)) == Z_STREAM_END)
			{
				break;
			}

			if (err != Z_OK)
			{
				return -1;
			}
		}

		if (deflateEnd(&c_stream) != Z_OK)
		{
			return -1;
		}

		*nzdata = c_stream.total_out;

		return 0;
	}
	return -1;
}



/* HTTP gzip decompress */
int Compress::httpgzdecompress(Byte *zdata, uLong nzdata, Byte *data, uLong *ndata)
{
	int err = 0;
	z_stream d_stream = {0}; /* decompression stream */
	static char dummy_head[2] = 
	{
		0x8 + 0x7 * 0x10,
		(((0x8 + 0x7 * 0x10) * 0x100 + 30) / 31 * 31) & 0xFF,
	};
	d_stream.zalloc = (alloc_func)0;
	d_stream.zfree = (free_func)0;
	d_stream.opaque = (voidpf)0;
	d_stream.next_in  = zdata;
	d_stream.avail_in = 0;
	d_stream.next_out = data;
	if(inflateInit2(&d_stream, 47) != Z_OK) 
		return -1;
	while (d_stream.total_out < *ndata && d_stream.total_in < nzdata) {
		d_stream.avail_in = d_stream.avail_out = 1; /* force small buffers */
		if((err = inflate(&d_stream, Z_NO_FLUSH)) == Z_STREAM_END) 
			break;
		if(err != Z_OK )
		{
			if(err == Z_DATA_ERROR)
			{
				d_stream.next_in = (Bytef*) dummy_head;
				d_stream.avail_in = sizeof(dummy_head);
				if((err = inflate(&d_stream, Z_NO_FLUSH)) != Z_OK) 
				{
					return -1;
				}
			}
			else return -1;
		}
	}
	if(inflateEnd(&d_stream) != Z_OK) 
		return -1;
	*ndata = d_stream.total_out;
	return 0;
}

/* Uncompress gzip data */
int Compress::gzdecompress(Byte *zdata, uLong nzdata, Byte *data, uLong *ndata)
{
	int err = 0;
	z_stream d_stream = {0}; /* decompression stream */
	static char dummy_head[2] = 
	{
		0x8 + 0x7 * 0x10,
		(((0x8 + 0x7 * 0x10) * 0x100 + 30) / 31 * 31) & 0xFF,
	};
	d_stream.zalloc = (alloc_func)0;
	d_stream.zfree = (free_func)0;
	d_stream.opaque = (voidpf)0;
	d_stream.next_in  = zdata;
	d_stream.avail_in = 0;
	d_stream.next_out = data;
	if(inflateInit2(&d_stream, -MAX_WBITS) != Z_OK) 
		return -1;
	//if(inflateInit2(&d_stream, 47) != Z_OK) 
	//return -1;
	while (d_stream.total_out < *ndata && d_stream.total_in < nzdata) {
		d_stream.avail_in = d_stream.avail_out = 1; /* force small buffers */
		if((err = inflate(&d_stream, Z_NO_FLUSH)) == Z_STREAM_END) 
			break;
		if(err != Z_OK )
		{
			if(err == Z_DATA_ERROR)
			{
				d_stream.next_in = (Bytef*) dummy_head;
				d_stream.avail_in = sizeof(dummy_head);
				if((err = inflate(&d_stream, Z_NO_FLUSH)) != Z_OK) 
				{
					return -1;
				}
			}
			else return -1;
		}
	}
	if(inflateEnd(&d_stream) != Z_OK) 
		return -1;
	*ndata = d_stream.total_out;
	return 0;
}












