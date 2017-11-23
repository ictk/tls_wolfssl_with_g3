#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <string>
#include "neoDebug.h"
#include "neoCoLib.h"
#include "wolfssl/debug_util.h"
using namespace std;

extern "C" void test_ecc()
{
	WC_RNG rng;
	BYTE buff[2048];
	word32 buffsize = 2048;
	ecc_key key,key2;
	word32 ret = 0;
	byte secret[1024]; // can hold 1024 byte shared secret pub
	word32 secretSz = sizeof(secret);
	byte secret2[1024]; // can hold 1024 byte shared secret pub
	word32 secretSz2 = sizeof(secret2);

	//const char * pubkey = "044A5B42C20E614F27DB01E7AC348BE234F9CB0E79BA3C08C7415A22F8C9EA7A3D24B9E008B8C7F37C775BA611C09236A7315C50BB1F5D1A64C8548CFCF5BDF90F";
	//const char * pribkey = "B4083C7036419F8CB7BA8368313F83F07DEFF63EDC87AEB9C03E8EA211F29A2B";

	VECBYTE pubkey = NCL::HexStr2Byte("044A5B42C20E614F27DB01E7AC348BE234F9CB0E79BA3C08C7415A22F8C9EA7A3D24B9E008B8C7F37C775BA611C09236A7315C50BB1F5D1A64C8548CFCF5BDF90F");
	VECBYTE privkey = NCL::HexStr2Byte("B4083C7036419F8CB7BA8368313F83F07DEFF63EDC87AEB9C03E8EA211F29A2B");
	
	fprintf(stderr, "%s\n", "TEST");

	
	fprintf(stderr, "%s\n", wc_ecc_get_name(ECC_SECP256R1));
	int curve_idx = wc_ecc_get_curve_idx(ECC_SECP256R1);
	wc_InitRng(&rng);
	//wc_RNG_GenerateBlock(&rng, buff, 256);
	wc_ecc_init(&key);
	ret = wc_ecc_make_key(&rng, 32, &key); // initialize 32 byte ecc key
	//ret = wc_ecc_make_key(&wc_rang, 256, &key);

	wc_InitRng(&rng);
	//wc_RNG_GenerateBlock(&rng, buff, 256);
	wc_ecc_init(&key2);
	wc_ecc_import_private_key_ex(&privkey[0], privkey.size(), &pubkey[0], pubkey.size(), &key2, ECC_SECP256R1);
	//ret = wc_ecc_make_key(&rng, 32, &key2); // initialize 32 byte ecc key
	

	buffsize = 2048;
	wc_ecc_export_private_only(&key, buff, &buffsize);
	print_hexdumpbin("priv", buff, buffsize);
	buffsize = 2048;
	wc_ecc_export_x963(&key, buff, &buffsize);
	print_hexdumpbin("pub", buff, buffsize);

	buffsize = 2048;
	wc_ecc_export_private_only(&key2, buff, &buffsize);
	print_hexdumpbin("priv 2", buff, buffsize);
	buffsize = 2048;
	wc_ecc_export_x963(&key2, buff, &buffsize);
	print_hexdumpbin("pub 2", buff, buffsize);
	
	buffsize = 2048;
	wc_ecc_export_x963_ex(&key2, buff, &buffsize,1);
	print_hexdumpbin("pub compressed 2", buff, buffsize);



	ret = wc_ecc_shared_secret(&key, &key2, secret, &secretSz); // generate secret key
	ret = wc_ecc_shared_secret(&key2, &key, secret2, &secretSz2); // generate secret key
	/*print_bin("test",secret, secretSz);
	print_hexdumpbin("test", secret, secretSz);*/
	string retaaa = NCL::BytetoHexStr(secret, secretSz);
	printf("%s\n", retaaa.c_str());
	if (ret != 0) {
		// error generating shared secret key
	}

	wc_FreeRng(&rng);

	printf("test ecc _test:%d ",ret);
}
