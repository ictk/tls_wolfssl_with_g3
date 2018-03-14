#include <wolfssl/wolfcrypt/ecc.h>
#include "neoDebug.h"
#include "neoCoLib.h"
#include "wolfssl/debug_util.h"
#include "wolfssl/user_ecc.h"
#include "sample_def.h"
#include"g3_api.h"



extern "C" void init_user_ecc(const char * st_com);
LPST_WC_ECC_FUNCTIONS _lpwc = NULL;
PF_WC_ECC_VERIFY_HASH _org_pf_wc_ecc_verify_hash;
int wc_ecc_verify_hash_new(const byte*  sig, word32 siglen, const byte*  hash, word32 hashlen, int*  stat, ecc_key*  key);
int init_sample_ieb100cdc(void *param);
void swap_bytes(void* value, int size)
{
	unsigned char * pvalue = (unsigned char *)value;
	unsigned char * pnewvalue = (unsigned char *)malloc(size);

	for (int i = 0; i < size; i++){
		*(pnewvalue + size - 1 - i) = *(pvalue + i);
	}
	memcpy(value, pnewvalue, size);
	free(pnewvalue);

}

SAMPLE_FUNCTIONS _cursamplefunction;
void get_functions_ieb100cdc(LPSAMPLE_FUNCTIONS lpsamplefunction);
void init_user_ecc(const char * st_com)
{

	get_functions_ieb100cdc(&_cursamplefunction);

	_cursamplefunction.init_sample((void*)st_com);
	_cursamplefunction.wake_up_and_convert_mode();


	_lpwc = get_user_wc_ecc_functions();
	_org_pf_wc_ecc_verify_hash = _lpwc->pf_wc_ecc_verify_hash;
	_lpwc->pf_wc_ecc_verify_hash = wc_ecc_verify_hash_new;
	unsigned char buff[32];
	int res_chall_size = 32;
	g3api_get_chellange(32, buff, &res_chall_size);
	print_bin("g3api_get_chellange", buff, res_chall_size);


}

int wc_ecc_verify_hash_new(const byte*  sig, word32 siglen, const byte*  hash, word32 hashlen, int*  stat, ecc_key*  key)
{
	//PRT_TITLE prttitle("wc_ecc_verify_hash");
	print_bin("FUCK      sig", sig, siglen);
	print_bin("FUCK      hash", hash, hashlen);

	int ret = _org_pf_wc_ecc_verify_hash(sig, siglen, hash, hashlen, stat, key);
	return ret;
}