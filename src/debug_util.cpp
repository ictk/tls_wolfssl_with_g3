#include "neoCoLib.h"
#include "wolfssl/debug_util.h"

FILE *_fpout = stderr;
void set_filepoint(FILE *fp){
	_fpout = fp;
}
void print_title(const char * title)
{
	fprintf(_fpout, "####NEO_API:%s\n", title);
}
void print_title_ext(const char * fmt,const char * title)
{
	fprintf(_fpout, fmt, title);
}

void print_pointer(const char * title,void * pt)
{
	fprintf(_fpout, "\n\n%s: 0x%x \n", title, pt);
}

void print_tls_title(const char * title)
{
	print_title_ext("\n\n\n\n!@#!@#!#!#!NEO_WOLFSSL_TLS_TITLE:%s\n", title);
	//fprintf(_fpout, "!@#!@#!#!#!NEO_WOLFSSL_TLS_TITLE:%s\n", title);
}

void print_bin(const char * title, const unsigned char * buff, int size)
{
	string retaaa = NCL::BytetoHexStr(buff, size);
	fprintf(_fpout, "\n*%s (size:%d):\n%s\n", title, size, retaaa.c_str());
}
void print_bin_ext(const char * fmt,const char * title, const unsigned char * buff, int size)
{
	string retaaa = NCL::BytetoHexStr(buff, size);
	fprintf(_fpout, fmt, title, size, retaaa.c_str());
}

void print_hexdumpbin(const char * title, const unsigned char * buff, int size)
{	print_bin(title,  buff,  size);

	return;
	unsigned char * pbuff = (unsigned char *)buff;
	int remainsize = size;
	int index = 0;
	int unitsize = 16;
	fprintf(_fpout, "HEXDUMP BEGIN\n\t%s (size:%d):\n", title, size);
#if 1 
	string retaaa = NCL::BytetoHexStr(buff, size);
	//fprintf(_fpout, "\t\t%s (size:%d):\n%s\n", title, size, retaaa.c_str());
	fprintf(_fpout, "\t\t%s\n", retaaa.c_str());
#else
	while (remainsize > 0){
		int realsize = min(unitsize, remainsize);
		string retaaa = NCL::BytetoHexStr(buff + index, realsize);
		fprintf(_fpout, "\t\t%s\n", retaaa.c_str());
		remainsize -= unitsize;
		index += unitsize;
	}
#endif
	fprintf(_fpout, "HEXDUMP END\n");
}

void print_intarray(const char * title, const unsigned int * buff, int size)
{
	unsigned int * pbuff = (unsigned int *)buff;
	int remainsize = size;
	int index = 0;
	int unitsize = 16;
	fprintf(_fpout, "HEXDUMP BEGIN\n\t%s (size:%d):\n", title, size);
	for (int i = 0; i < size;i++)
	{
		fprintf(_fpout, "\t\t0x%x\n", *pbuff);
		pbuff++;
	}

	fprintf(_fpout, "HEXDUMP END\n");
}
void print_msg(const char * title, const char * msg)
{
	fprintf(_fpout,"%s : %s\n", title,msg);
	
}