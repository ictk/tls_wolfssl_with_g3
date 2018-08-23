#define NULL 0
#include "CSerialRS232.h"
#include "neoCoLib.h"




#include "neoDebug.h"
#include "g3_api.h"
#include "g3_io_lib.h"

#include "stdio.h"
#ifndef min
#define min(a,b)    (((a) < (b)) ? (a) : (b))
#endif



void swap_bytes(void* value, int size);


extern FILE * _fp;

// DEFINE AS YOU WANT
typedef struct _tagINTER_PARAMS{
	

	char name[256];
	int param1;

}INTER_PARAMS, *LPINTER_PARAMS;

INTER_PARAMS _inter_params = { 0, };


extern "C" int init_sample_custome(void *param);
extern "C" int wake_up_and_convert_mode_custome();
extern "C" void end_sample_custome();
extern "C" void get_functions_custome(LPST_G3_IO_LIB_FUNCTIONS lpsamplefunction);

ST_G3_IO_LIB_FUNCTIONS  _samplefunction= {
	init_sample_custome,
	wake_up_and_convert_mode_custome,
	end_sample_custome

};

//###################################################	
/**
*   @brief	Gets the structure for initializing the ieb-100
*
*	@param	lpsamplefunction	: Pointer to a ST_G3_IO_LIB_FUNCTIONS structure that contains functions to initialize the device
*
*   @return void
*/
//###################################################
void get_functions_custome(LPST_G3_IO_LIB_FUNCTIONS lpsamplefunction)
{
	*lpsamplefunction = _samplefunction;

}


//INTER_PARAMS _inter_params = { 0, };



//###################################################	
/**
*   @brief	Sends the command and read the response from the device
*
*	@param	snd			: Pointer to send data buffer
*	@param	snd_size	: Size of snd data
*	@param	recv		: Pointer to receive data buffer
*	@param	recv_size	: Size of receive data
*	@param	etcparam	: Com port number
*
*   @return result
*/
//###################################################

extern "C"  int CALLTYPE send_n_recv(const unsigned char*snd, int snd_size, unsigned char*recv, int* recv_size, void*etcparam)
{

	unsigned char recv_buff[256] = { 0x04, 0x00, 0x03,0x40 };
	int real_recv_size = 4;
	INTER_PARAMS *pinter_params = (INTER_PARAMS*)etcparam;
	
	fprintf(_fp, "pinter_params %s %d\n", pinter_params->name, pinter_params->param1);

	fprintf(_fp,"send_n_recv\n");
	fprintf(_fp,"PURE SND: %s (%d)\n", NCL::BytetoHexStr(snd, snd_size).c_str(), snd_size);
	

	//SND EXCUTE 

	//RND EXCUTE
	

	memcpy(recv, recv_buff, real_recv_size);
	*recv_size = real_recv_size;

	fprintf(_fp, "RECV %s (%d) \n", NCL::BytetoHexStr(recv_buff, real_recv_size).c_str(), real_recv_size);



	return 0;
}


//###################################################	
/**
*   @brief	Initializes the ieb-100 board.
*
*	@param	param	: Com port number
*
*   @return result
*/
//###################################################
int init_sample_custome(void *param)
{
	char *str_param = (char *)param;
	
	
	_inter_params.param1 = 24;
	strcpy(_inter_params.name, "DUMMY TEST INIT");

	g3api_set_user_send_recv_pf(send_n_recv, &_inter_params);
	//int io open or create

	
	return 0;


}

//###################################################	
/**
*   @brief	Disconnects the ieb-100 board
*
*   @return void
*/
//###################################################
void end_sample_custome()
{
	
}


//###################################################	
/**
*   @brief	Wakes the g3
*
*   @return result
*/
//###################################################
int wake_up_and_convert_mode_custome()
{
	

	return 0;
}

void convert_up(){

}
