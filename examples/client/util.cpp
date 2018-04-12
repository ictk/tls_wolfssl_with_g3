#include "neoCoLib.h"

extern "C" void csleep(unsigned int msec)
{
	NCL::Sleep(msec);
}