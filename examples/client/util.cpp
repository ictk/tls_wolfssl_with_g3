#include "neoCoLib.h"

extern "C" void csleep(unsigned int msec)
{
	NCL::Sleep(msec);
}

extern FILE * _fp;

void print_result(const char * title,int ret)
{
	fprintf(_fp,"\n%s ret:0x%x \n", title, ret);
}

void print_value(const char * title, const void *buff,int size)
{
	fprintf(_fp,"\n%s %s %d \n", title, NCL::BytetoHexStr(buff, size).c_str(), size);
}
void print_result_value(const char * title, int ret,const void *buff, int size)
{
	fprintf(_fp,"\n%s ret:0x%x\n%s %d \n", title, ret,NCL::BytetoHexStr(buff, size).c_str(), size);
}
void cur_sleep(int wakeupTime)
{

	NCL::Sleep(wakeupTime);
}