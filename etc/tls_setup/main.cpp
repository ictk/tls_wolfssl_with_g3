// console_g3_api.cpp : 콘솔 응용 프로그램에 대한 진입점을 정의합니다.
//

//#include "stdafx.h"
//#include "CtrlBASE.h"


#include "CSerialRS232.h"
#include "neoCoLib.h"
#include "neoDebug.h"
#include <g3_api.h>
#include "g3_io_lib.h"
#include "util.h"
//#include<windows.h>



//#pragma comment(lib,"libBASE.lib")

using namespace  neocolib;



void test_load();
void tls_setup();
void clear();

FILE * _fp = stdout;


void init_fp(){

	_fp = fopen("out.txt", "wb");
	//g3api_set_fp(_fp);
}
int main(int argc, char* argv[])
{
	int ret = 0;
	
	
	
	NEO_START;

	NEO_TITLE(main);
	if (argc < 2){
		printf("\n1st argument must be serial port name\n");
		return -1;
	}
	const char *pchar = g3api_get_lib_version();


	printf("%s", pchar);
	printf("\nserila port name : (%s) \n",argv[1]);
	//init_fp();
	ST_G3_IO_LIB_FUNCTIONS samplefunction;
	//get_functions(G3_IO_IEVB100_FT4222, &samplefunction);
	get_functions(G3_IO_IEVB100_FT4222, &samplefunction);
	//GET_FUCNTION(&samplefunction);



	PF_INIT_G3_IO_LIB init_sample = samplefunction.init_sample;
	PF_WAKE_UP_AND_CONVERT_MODE wake_up_and_convert_mode = samplefunction.wake_up_and_convert_mode;
	PF_END_G3_IO_LIB end_sample = samplefunction.end_sample;



	if (init_sample(argv[1])){
		return -1;
	}
	if (wake_up_and_convert_mode()){
		return -1;

	}
	;

	
	tls_setup();
	//clear();
	
	return 0;

	
	NEO_TITLE(END);
	return 0;
}

