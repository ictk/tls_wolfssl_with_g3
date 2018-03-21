

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

/* in case user set HAVE_ECC there */
#include <wolfssl/wolfcrypt/settings.h>
#include "wolfssl/debug_util.h"
#include "wolfssl/user_bypass.h"

#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/error-crypt.h>



#include <wolfssl/wolfcrypt/ecc.h>
#include "wolfssl/user_bypass.h"
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/ssl.h>
#include <wolfssl/ssl.h>


#define WOLFSSL_MISC_INCLUDED
#include <wolfcrypt/src/misc.c>




const ecc_set_type ecc_sets[] = {
#ifdef ECC112
#ifndef NO_ECC_SECP
{
14,                             /* size/bytes */
ECC_SECP112R1,                  /* ID         */
"SECP112R1",                    /* curve name */
"DB7C2ABF62E35E668076BEAD208B", /* prime      */
"DB7C2ABF62E35E668076BEAD2088", /* A          */
"659EF8BA043916EEDE8911702B22", /* B          */
"DB7C2ABF62E35E7628DFAC6561C5", /* order      */
"9487239995A5EE76B55F9C2F098",  /* Gx         */
"A89CE5AF8724C0A23E0E0FF77500", /* Gy         */
ecc_oid_secp112r1,              /* oid/oidSz  */
sizeof(ecc_oid_secp112r1) / sizeof(ecc_oid_t),
ECC_SECP112R1_OID,              /* oid sum    */
1,                              /* cofactor   */
},
#endif /* !NO_ECC_SECP */
#ifdef HAVE_ECC_SECPR2
{
14,                             /* size/bytes */
ECC_SECP112R2,                  /* ID         */
"SECP112R2",                    /* curve name */
"DB7C2ABF62E35E668076BEAD208B", /* prime      */
"6127C24C05F38A0AAAF65C0EF02C", /* A          */
"51DEF1815DB5ED74FCC34C85D709", /* B          */
"36DF0AAFD8B8D7597CA10520D04B", /* order      */
"4BA30AB5E892B4E1649DD0928643", /* Gx         */
"ADCD46F5882E3747DEF36E956E97", /* Gy         */
ecc_oid_secp112r2,              /* oid/oidSz  */
sizeof(ecc_oid_secp112r2) / sizeof(ecc_oid_t),
ECC_SECP112R2_OID,              /* oid sum    */
4,                              /* cofactor   */
},
#endif /* HAVE_ECC_SECPR2 */
#endif /* ECC112 */
#ifdef ECC128
#ifndef NO_ECC_SECP
{
16,                                 /* size/bytes */
ECC_SECP128R1,                      /* ID         */
"SECP128R1",                        /* curve name */
"FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF", /* prime      */
"FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFC", /* A          */
"E87579C11079F43DD824993C2CEE5ED3", /* B          */
"FFFFFFFE0000000075A30D1B9038A115", /* order      */
"161FF7528B899B2D0C28607CA52C5B86", /* Gx         */
"CF5AC8395BAFEB13C02DA292DDED7A83", /* Gy         */
ecc_oid_secp128r1,                  /* oid/oidSz  */
sizeof(ecc_oid_secp128r1) / sizeof(ecc_oid_t),
ECC_SECP128R1_OID,                  /* oid sum    */
1,                                  /* cofactor   */
},
#endif /* !NO_ECC_SECP */
#ifdef HAVE_ECC_SECPR2
{
16,                                 /* size/bytes */
ECC_SECP128R2,                      /* ID         */
"SECP128R2",                        /* curve name */
"FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF", /* prime      */
"D6031998D1B3BBFEBF59CC9BBFF9AEE1", /* A          */
"5EEEFCA380D02919DC2C6558BB6D8A5D", /* B          */
"3FFFFFFF7FFFFFFFBE0024720613B5A3", /* order      */
"7B6AA5D85E572983E6FB32A7CDEBC140", /* Gx         */
"27B6916A894D3AEE7106FE805FC34B44", /* Gy         */
ecc_oid_secp128r2,                  /* oid/oidSz  */
sizeof(ecc_oid_secp128r2) / sizeof(ecc_oid_t),
ECC_SECP128R2_OID,                  /* oid sum    */
4,                                  /* cofactor   */
},
#endif /* HAVE_ECC_SECPR2 */
#endif /* ECC128 */
#ifdef ECC160
#ifndef NO_ECC_SECP
{
20,                                         /* size/bytes */
ECC_SECP160R1,                              /* ID         */
"SECP160R1",                                /* curve name */
"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF", /* prime      */
"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC", /* A          */
"1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45", /* B          */
"100000000000000000001F4C8F927AED3CA752257",/* order      */
"4A96B5688EF573284664698968C38BB913CBFC82", /* Gx         */
"23A628553168947D59DCC912042351377AC5FB32", /* Gy         */
ecc_oid_secp160r1,                          /* oid/oidSz  */
sizeof(ecc_oid_secp160r1) / sizeof(ecc_oid_t),
ECC_SECP160R1_OID,                          /* oid sum    */
1,                                          /* cofactor   */
},
#endif /* !NO_ECC_SECP */
#ifdef HAVE_ECC_SECPR2
{
20,                                         /* size/bytes */
ECC_SECP160R2,                              /* ID         */
"SECP160R2",                                /* curve name */
"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73", /* prime      */
"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC70", /* A          */
"B4E134D3FB59EB8BAB57274904664D5AF50388BA", /* B          */
"100000000000000000000351EE786A818F3A1A16B",/* order      */
"52DCB034293A117E1F4FF11B30F7199D3144CE6D", /* Gx         */
"FEAFFEF2E331F296E071FA0DF9982CFEA7D43F2E", /* Gy         */
ecc_oid_secp160r2,                          /* oid/oidSz  */
sizeof(ecc_oid_secp160r2) / sizeof(ecc_oid_t),
ECC_SECP160R2_OID,                          /* oid sum    */
1,                                          /* cofactor   */
},
#endif /* HAVE_ECC_SECPR2 */
#ifdef HAVE_ECC_KOBLITZ
{
20,                                         /* size/bytes */
ECC_SECP160K1,                              /* ID         */
"SECP160K1",                                /* curve name */
"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73", /* prime      */
"0000000000000000000000000000000000000000", /* A          */
"0000000000000000000000000000000000000007", /* B          */
"100000000000000000001B8FA16DFAB9ACA16B6B3",/* order      */
"3B4C382CE37AA192A4019E763036F4F5DD4D7EBB", /* Gx         */
"938CF935318FDCED6BC28286531733C3F03C4FEE", /* Gy         */
ecc_oid_secp160k1,                          /* oid/oidSz  */
sizeof(ecc_oid_secp160k1) / sizeof(ecc_oid_t),
ECC_SECP160K1_OID,                          /* oid sum    */
1,                                          /* cofactor   */
},
#endif /* HAVE_ECC_KOBLITZ */
#ifdef HAVE_ECC_BRAINPOOL
{
20,                                         /* size/bytes */
ECC_BRAINPOOLP160R1,                        /* ID         */
"BRAINPOOLP160R1",                          /* curve name */
"E95E4A5F737059DC60DFC7AD95B3D8139515620F", /* prime      */
"340E7BE2A280EB74E2BE61BADA745D97E8F7C300", /* A          */
"1E589A8595423412134FAA2DBDEC95C8D8675E58", /* B          */
"E95E4A5F737059DC60DF5991D45029409E60FC09", /* order      */
"BED5AF16EA3F6A4F62938C4631EB5AF7BDBCDBC3", /* Gx         */
"1667CB477A1A8EC338F94741669C976316DA6321", /* Gy         */
ecc_oid_brainpoolp160r1,                    /* oid/oidSz  */
sizeof(ecc_oid_brainpoolp160r1) / sizeof(ecc_oid_t),
ECC_BRAINPOOLP160R1_OID,                    /* oid sum    */
1,                                          /* cofactor   */
},
#endif /* HAVE_ECC_BRAINPOOL */
#endif /* ECC160 */
#ifdef ECC192
#ifndef NO_ECC_SECP
{
24,                                                 /* size/bytes */
ECC_SECP192R1,                                      /* ID         */
"SECP192R1",                                        /* curve name */
"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", /* prime      */
"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC", /* A          */
"64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1", /* B          */
"FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831", /* order      */
"188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", /* Gx         */
"7192B95FFC8DA78631011ED6B24CDD573F977A11E794811",  /* Gy         */
ecc_oid_secp192r1,                                  /* oid/oidSz  */
sizeof(ecc_oid_secp192r1) / sizeof(ecc_oid_t),
ECC_SECP192R1_OID,                                  /* oid sum    */
1,                                                  /* cofactor   */
},
#endif /* !NO_ECC_SECP */
#ifdef HAVE_ECC_SECPR2
{
24,                                                 /* size/bytes */
ECC_PRIME192V2,                                     /* ID         */
"PRIME192V2",                                       /* curve name */
"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", /* prime      */
"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC", /* A          */
"CC22D6DFB95C6B25E49C0D6364A4E5980C393AA21668D953", /* B          */
"FFFFFFFFFFFFFFFFFFFFFFFE5FB1A724DC80418648D8DD31", /* order      */
"EEA2BAE7E1497842F2DE7769CFE9C989C072AD696F48034A", /* Gx         */
"6574D11D69B6EC7A672BB82A083DF2F2B0847DE970B2DE15", /* Gy         */
ecc_oid_prime192v2,                                 /* oid/oidSz  */
sizeof(ecc_oid_prime192v2) / sizeof(ecc_oid_t),
ECC_PRIME192V2_OID,                                 /* oid sum    */
1,                                                  /* cofactor   */
},
#endif /* HAVE_ECC_SECPR2 */
#ifdef HAVE_ECC_SECPR3
{
24,                                                 /* size/bytes */
ECC_PRIME192V3,                                     /* ID         */
"PRIME192V3",                                       /* curve name */
"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", /* prime      */
"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC", /* A          */
"22123DC2395A05CAA7423DAECCC94760A7D462256BD56916", /* B          */
"FFFFFFFFFFFFFFFFFFFFFFFF7A62D031C83F4294F640EC13", /* order      */
"7D29778100C65A1DA1783716588DCE2B8B4AEE8E228F1896", /* Gx         */
"38A90F22637337334B49DCB66A6DC8F9978ACA7648A943B0", /* Gy         */
ecc_oid_prime192v3,                                 /* oid/oidSz  */
sizeof(ecc_oid_prime192v3) / sizeof(ecc_oid_t),
ECC_PRIME192V3_OID,                                 /* oid sum    */
1,                                                  /* cofactor   */
},
#endif /* HAVE_ECC_SECPR3 */
#ifdef HAVE_ECC_KOBLITZ
{
24,                                                 /* size/bytes */
ECC_SECP192K1,                                      /* ID         */
"SECP192K1",                                        /* curve name */
"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37", /* prime      */
"000000000000000000000000000000000000000000000000", /* A          */
"000000000000000000000000000000000000000000000003", /* B          */
"FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D", /* order      */
"DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D", /* Gx         */
"9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D", /* Gy         */
ecc_oid_secp192k1,                                  /* oid/oidSz  */
sizeof(ecc_oid_secp192k1) / sizeof(ecc_oid_t),
ECC_SECP192K1_OID,                                  /* oid sum    */
1,                                                  /* cofactor   */
},
#endif /* HAVE_ECC_KOBLITZ */
#ifdef HAVE_ECC_BRAINPOOL
{
24,                                                 /* size/bytes */
ECC_BRAINPOOLP192R1,                                /* ID         */
"BRAINPOOLP192R1",                                  /* curve name */
"C302F41D932A36CDA7A3463093D18DB78FCE476DE1A86297", /* prime      */
"6A91174076B1E0E19C39C031FE8685C1CAE040E5C69A28EF", /* A          */
"469A28EF7C28CCA3DC721D044F4496BCCA7EF4146FBF25C9", /* B          */
"C302F41D932A36CDA7A3462F9E9E916B5BE8F1029AC4ACC1", /* order      */
"C0A0647EAAB6A48753B033C56CB0F0900A2F5C4853375FD6", /* Gx         */
"14B690866ABD5BB88B5F4828C1490002E6773FA2FA299B8F", /* Gy         */
ecc_oid_brainpoolp192r1,                            /* oid/oidSz  */
sizeof(ecc_oid_brainpoolp192r1) / sizeof(ecc_oid_t),
ECC_BRAINPOOLP192R1_OID,                            /* oid sum    */
1,                                                  /* cofactor   */
},
#endif /* HAVE_ECC_BRAINPOOL */
#endif /* ECC192 */
#ifdef ECC224
#ifndef NO_ECC_SECP
{
28,                                                         /* size/bytes */
ECC_SECP224R1,                                              /* ID         */
"SECP224R1",                                                /* curve name */
"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001", /* prime      */
"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE", /* A          */
"B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4", /* B          */
"FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D", /* order      */
"B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21", /* Gx         */
"BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34", /* Gy         */
ecc_oid_secp224r1,                                          /* oid/oidSz  */
sizeof(ecc_oid_secp224r1) / sizeof(ecc_oid_t),
ECC_SECP224R1_OID,                                          /* oid sum    */
1,                                                          /* cofactor   */
},
#endif /* !NO_ECC_SECP */
#ifdef HAVE_ECC_KOBLITZ
{
28,                                                         /* size/bytes */
ECC_SECP224K1,                                              /* ID         */
"SECP224K1",                                                /* curve name */
"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D", /* prime      */
"00000000000000000000000000000000000000000000000000000000", /* A          */
"00000000000000000000000000000000000000000000000000000005", /* B          */
"10000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7",/* order      */
"A1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C", /* Gx         */
"7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5", /* Gy         */
ecc_oid_secp224k1,                                          /* oid/oidSz  */
sizeof(ecc_oid_secp224k1) / sizeof(ecc_oid_t),
ECC_SECP224K1_OID,                                          /* oid sum    */
1,                                                          /* cofactor   */
},
#endif /* HAVE_ECC_KOBLITZ */
#ifdef HAVE_ECC_BRAINPOOL
{
28,                                                         /* size/bytes */
ECC_BRAINPOOLP224R1,                                        /* ID         */
"BRAINPOOLP224R1",                                          /* curve name */
"D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF", /* prime      */
"68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43", /* A          */
"2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B", /* B          */
"D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F", /* order      */
"0D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D", /* Gx         */
"58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD", /* Gy         */
ecc_oid_brainpoolp224r1,                                    /* oid/oidSz  */
sizeof(ecc_oid_brainpoolp224r1) / sizeof(ecc_oid_t),
ECC_BRAINPOOLP224R1_OID,                                    /* oid sum    */
1,                                                          /* cofactor   */
},
#endif /* HAVE_ECC_BRAINPOOL */
#endif /* ECC224 */
#ifdef ECC239
#ifndef NO_ECC_SECP
{
30,                                                             /* size/bytes */
ECC_PRIME239V1,                                                 /* ID         */
"PRIME239V1",                                                   /* curve name */
"7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFF", /* prime      */
"7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFC", /* A          */
"6B016C3BDCF18941D0D654921475CA71A9DB2FB27D1D37796185C2942C0A", /* B          */
"7FFFFFFFFFFFFFFFFFFFFFFF7FFFFF9E5E9A9F5D9071FBD1522688909D0B", /* order      */
"0FFA963CDCA8816CCC33B8642BEDF905C3D358573D3F27FBBD3B3CB9AAAF", /* Gx         */
"7DEBE8E4E90A5DAE6E4054CA530BA04654B36818CE226B39FCCB7B02F1AE", /* Gy         */
ecc_oid_prime239v1,                                             /* oid/oidSz  */
sizeof(ecc_oid_prime239v1) / sizeof(ecc_oid_t),
ECC_PRIME239V1_OID,                                             /* oid sum    */
1,                                                              /* cofactor   */
},
#endif /* !NO_ECC_SECP */
#ifdef HAVE_ECC_SECPR2
{
30,                                                             /* size/bytes */
ECC_PRIME239V2,                                                 /* ID         */
"PRIME239V2",                                                   /* curve name */
"7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFF", /* prime      */
"7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFC", /* A          */
"617FAB6832576CBBFED50D99F0249C3FEE58B94BA0038C7AE84C8C832F2C", /* B          */
"7FFFFFFFFFFFFFFFFFFFFFFF800000CFA7E8594377D414C03821BC582063", /* order      */
"38AF09D98727705120C921BB5E9E26296A3CDCF2F35757A0EAFD87B830E7", /* Gx         */
"5B0125E4DBEA0EC7206DA0FC01D9B081329FB555DE6EF460237DFF8BE4BA", /* Gy         */
ecc_oid_prime239v2,                                             /* oid/oidSz  */
sizeof(ecc_oid_prime239v2) / sizeof(ecc_oid_t),
ECC_PRIME239V2_OID,                                             /* oid sum    */
1,                                                              /* cofactor   */
},
#endif /* HAVE_ECC_SECPR2 */
#ifdef HAVE_ECC_SECPR3
{
30,                                                             /* size/bytes */
ECC_PRIME239V3,                                                 /* ID         */
"PRIME239V3",                                                   /* curve name */
"7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFF", /* prime      */
"7FFFFFFFFFFFFFFFFFFFFFFF7FFFFFFFFFFF8000000000007FFFFFFFFFFC", /* A          */
"255705FA2A306654B1F4CB03D6A750A30C250102D4988717D9BA15AB6D3E", /* B          */
"7FFFFFFFFFFFFFFFFFFFFFFF7FFFFF975DEB41B3A6057C3C432146526551", /* order      */
"6768AE8E18BB92CFCF005C949AA2C6D94853D0E660BBF854B1C9505FE95A", /* Gx         */
"1607E6898F390C06BC1D552BAD226F3B6FCFE48B6E818499AF18E3ED6CF3", /* Gy         */
ecc_oid_prime239v3,                                             /* oid/oidSz  */
sizeof(ecc_oid_prime239v3) / sizeof(ecc_oid_t),
ECC_PRIME239V3_OID,                                             /* oid sum    */
1,                                                              /* cofactor   */
},
#endif /* HAVE_ECC_SECPR3 */
#endif /* ECC239 */
#ifdef ECC256
#ifndef NO_ECC_SECP
{
	32,                                                                 /* size/bytes */
	ECC_SECP256R1,                                                      /* ID         */
	"SECP256R1",                                                        /* curve name */
	"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", /* prime      */
	"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", /* A          */
	"5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", /* B          */
	"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", /* order      */
	"6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", /* Gx         */
	"4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", /* Gy         */
	ecc_oid_secp256r1,                                                  /* oid/oidSz  */
	sizeof(ecc_oid_secp256r1) / sizeof(ecc_oid_t),
	ECC_SECP256R1_OID,                                                  /* oid sum    */
	1,                                                                  /* cofactor   */
},
#endif /* !NO_ECC_SECP */
#ifdef HAVE_ECC_KOBLITZ
	{
		32,                                                                 /* size/bytes */
		ECC_SECP256K1,                                                      /* ID         */
		"SECP256K1",                                                        /* curve name */
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", /* prime      */
		"0000000000000000000000000000000000000000000000000000000000000000", /* A          */
		"0000000000000000000000000000000000000000000000000000000000000007", /* B          */
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", /* order      */
		"79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", /* Gx         */
		"483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", /* Gy         */
		ecc_oid_secp256k1,                                                  /* oid/oidSz  */
		sizeof(ecc_oid_secp256k1) / sizeof(ecc_oid_t),
		ECC_SECP256K1_OID,                                                  /* oid sum    */
		1,                                                                  /* cofactor   */
	},
#endif /* HAVE_ECC_KOBLITZ */
#ifdef HAVE_ECC_BRAINPOOL
		{
			32,                                                                 /* size/bytes */
			ECC_BRAINPOOLP256R1,                                                /* ID         */
			"BRAINPOOLP256R1",                                                  /* curve name */
			"A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377", /* prime      */
			"7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9", /* A          */
			"26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6", /* B          */
			"A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7", /* order      */
			"8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262", /* Gx         */
			"547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997", /* Gy         */
			ecc_oid_brainpoolp256r1,                                            /* oid/oidSz  */
			sizeof(ecc_oid_brainpoolp256r1) / sizeof(ecc_oid_t),
			ECC_BRAINPOOLP256R1_OID,                                            /* oid sum    */
			1,                                                                  /* cofactor   */
		},
#endif /* HAVE_ECC_BRAINPOOL */
#endif /* ECC256 */
#ifdef ECC320
#ifdef HAVE_ECC_BRAINPOOL
			{
				40,                                                                                 /* size/bytes */
				ECC_BRAINPOOLP320R1,                                                                /* ID         */
				"BRAINPOOLP320R1",                                                                  /* curve name */
				"D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27", /* prime      */
				"3EE30B568FBAB0F883CCEBD46D3F3BB8A2A73513F5EB79DA66190EB085FFA9F492F375A97D860EB4", /* A          */
				"520883949DFDBC42D3AD198640688A6FE13F41349554B49ACC31DCCD884539816F5EB4AC8FB1F1A6", /* B          */
				"D35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311", /* order      */
				"43BD7E9AFB53D8B85289BCC48EE5BFE6F20137D10A087EB6E7871E2A10A599C710AF8D0D39E20611", /* Gx         */
				"14FDD05545EC1CC8AB4093247F77275E0743FFED117182EAA9C77877AAAC6AC7D35245D1692E8EE1", /* Gy         */
				ecc_oid_brainpoolp320r1, sizeof(ecc_oid_brainpoolp320r1) / sizeof(ecc_oid_t),       /* oid/oidSz  */
				ECC_BRAINPOOLP320R1_OID,                                                            /* oid sum    */
				1,                                                                                  /* cofactor   */
			},
#endif /* HAVE_ECC_BRAINPOOL */
#endif /* ECC320 */
#ifdef ECC384
#ifndef NO_ECC_SECP
				{
					48,                                                                                                 /* size/bytes */
					ECC_SECP384R1,                                                                                      /* ID         */
					"SECP384R1",                                                                                        /* curve name */
					"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF", /* prime      */
					"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC", /* A          */
					"B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF", /* B          */
					"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973", /* order      */
					"AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7", /* Gx         */
					"3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F", /* Gy         */
					ecc_oid_secp384r1, sizeof(ecc_oid_secp384r1) / sizeof(ecc_oid_t),                                   /* oid/oidSz  */
					ECC_SECP384R1_OID,                                                                                  /* oid sum    */
					1,                                                                                                  /* cofactor   */
				},
#endif /* !NO_ECC_SECP */
#ifdef HAVE_ECC_BRAINPOOL
					{
						48,                                                                                                 /* size/bytes */
						ECC_BRAINPOOLP384R1,                                                                                /* ID         */
						"BRAINPOOLP384R1",                                                                                  /* curve name */
						"8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53", /* prime      */
						"7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826", /* A          */
						"04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11", /* B          */
						"8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565", /* order      */
						"1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E", /* Gx         */
						"8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315", /* Gy         */
						ecc_oid_brainpoolp384r1, sizeof(ecc_oid_brainpoolp384r1) / sizeof(ecc_oid_t),                       /* oid/oidSz  */
						ECC_BRAINPOOLP384R1_OID,                                                                            /* oid sum    */
						1,                                                                                                  /* cofactor   */
					},
#endif /* HAVE_ECC_BRAINPOOL */
#endif /* ECC384 */
#ifdef ECC512
#ifdef HAVE_ECC_BRAINPOOL
						{
							64,                                                                                                                                 /* size/bytes */
							ECC_BRAINPOOLP512R1,                                                                                                                /* ID         */
							"BRAINPOOLP512R1",                                                                                                                  /* curve name */
							"AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3", /* prime      */
							"7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA", /* A          */
							"3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723", /* B          */
							"AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069", /* order      */
							"81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822", /* Gx         */
							"7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892", /* Gy         */
							ecc_oid_brainpoolp512r1, sizeof(ecc_oid_brainpoolp512r1) / sizeof(ecc_oid_t),                                                       /* oid/oidSz  */
							ECC_BRAINPOOLP512R1_OID,                                                                                                            /* oid sum    */
							1,                                                                                                                                  /* cofactor   */
						},
#endif /* HAVE_ECC_BRAINPOOL */
#endif /* ECC512 */
#ifdef ECC521
#ifndef NO_ECC_SECP
							{
								66,                                                                                                                                    /* size/bytes */
								ECC_SECP521R1,                                                                                                                         /* ID         */
								"SECP521R1",                                                                                                                           /* curve name */
								"1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", /* prime      */
								"1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC", /* A          */
								"51953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",  /* B          */
								"1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409", /* order      */
								"C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",  /* Gx         */
								"11839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650", /* Gy         */
								ecc_oid_secp521r1, sizeof(ecc_oid_secp521r1) / sizeof(ecc_oid_t),                                                                      /* oid/oidSz  */
								ECC_SECP521R1_OID,                                                                                                                     /* oid sum    */
								1,                                                                                                                                     /* cofactor   */
							},
#endif /* !NO_ECC_SECP */
#endif /* ECC521 */
#if defined(WOLFSSL_CUSTOM_CURVES) && defined(ECC_CACHE_CURVE)
							/* place holder for custom curve index for cache */
								{
									1, /* non-zero */
									ECC_CURVE_CUSTOM,
									NULL, NULL, NULL, NULL, NULL, NULL, NULL,
									NULL, 0, 0, 0
								},
#endif
									{
										0, -1,
										NULL, NULL, NULL, NULL, NULL, NULL, NULL,
										NULL, 0, 0, 0
									}
};



//START DEC_ALL
const char*  wc_ecc_get_name_org(int curve_id)
{
	return 0;
}
int ecc_projective_add_point_org(ecc_point* P,ecc_point* Q,ecc_point* R,mp_int* a,mp_int* modulus,mp_digit mp)
{
	return 0;
}
int ecc_projective_dbl_point_org(ecc_point* P,ecc_point* R,mp_int* a,mp_int* modulus,mp_digit mp)
{
	return 0;
}
int wc_ecc_make_key_org(WC_RNG* rng,int keysize,ecc_key* key)
{
	return 0;
}
int wc_ecc_make_key_ex_org(WC_RNG* rng,int keysize,ecc_key* key,int curve_id)
{
	return 0;
}
int wc_ecc_make_pub_org(ecc_key* key,ecc_point* pubOut)
{
	return 0;
}
int wc_ecc_check_key_org(ecc_key* key)
{
	return 0;
}
int wc_ecc_is_point_org(ecc_point* ecp,mp_int* a,mp_int* b,mp_int* prime)
{
	return 0;
}
int wc_ecc_shared_secret_org(ecc_key* private_key,ecc_key* public_key,byte* out,word32* outlen)
{
	return 0;
}
int wc_ecc_shared_secret_gen_org(ecc_key* private_key,ecc_point* point,byte* out,word32 * outlen)
{
	return 0;
}
int wc_ecc_shared_secret_ex_org(ecc_key* private_key,ecc_point* point,byte* out,word32 * outlen)
{
	return 0;
}
int wc_ecc_sign_hash_org(const byte* in,word32 inlen,byte* out,word32 * outlen,WC_RNG* rng,ecc_key* key)
{
	return 0;
}
int wc_ecc_sign_hash_ex_org(const byte* in,word32 inlen,WC_RNG* rng,ecc_key* key,mp_int * r,mp_int * s)
{
	return 0;
}
int wc_ecc_verify_hash_org(const byte* sig,word32 siglen,const byte* hash,word32 hashlen,int* stat,ecc_key* key)
{
	return 0;
}
int wc_ecc_verify_hash_ex_org(mp_int * r,mp_int * s,const byte* hash,word32 hashlen,int* stat,ecc_key* key)
{
	return 0;
}
int wc_ecc_init_org(ecc_key* key)
{
	return 0;
}
int wc_ecc_init_ex_org(ecc_key* key,void* heap,int devId)
{
	return 0;
}
void wc_ecc_free_org(ecc_key* key)
{

}
int wc_ecc_set_flags_org(ecc_key* key,word32 flags)
{
	return 0;
}
int wc_ecc_set_curve_org(ecc_key* key,int keysize,int curve_id)
{
	return 0;
}
int wc_ecc_is_valid_idx_org(int n)
{
	return 0;
}
int wc_ecc_get_curve_idx_org(int curve_id)
{
	return 0;
}
int wc_ecc_get_curve_id_org(int curve_idx)
{
	return 0;
}
int wc_ecc_get_curve_size_from_id_org(int curve_id)
{
	return 0;
}
int wc_ecc_get_curve_idx_from_name_org(const char* curveName)
{
	return 0;
}
int wc_ecc_get_curve_size_from_name_org(const char* curveName)
{
	return 0;
}
int wc_ecc_get_curve_id_from_name_org(const char* curveName)
{
	return 0;
}
int wc_ecc_get_curve_id_from_params_org(int fieldSize,const byte* prime,word32 primeSz,const byte* Af,word32 AfSz,const byte* Bf,word32 BfSz,const byte* order,word32 orderSz,const byte* Gx,word32 GxSz,const byte* Gy,word32 GySz,int cofactor)
{
	return 0;
}
ecc_point*  wc_ecc_new_point_org()
{
	return 0;
}
ecc_point*  wc_ecc_new_point_h_org(void* h)
{
	return 0;
}
void wc_ecc_del_point_org(ecc_point* p)
{

}
void wc_ecc_del_point_h_org(ecc_point* p,void* h)
{

}
int wc_ecc_copy_point_org(ecc_point* p,ecc_point * r)
{
	return 0;
}
int wc_ecc_cmp_point_org(ecc_point* a,ecc_point * b)
{
	return 0;
}
int wc_ecc_point_is_at_infinity_org(ecc_point * p)
{
	return 0;
}
int wc_ecc_mulmod_org(mp_int* k,ecc_point * G,ecc_point * R,mp_int* a,mp_int* modulus,int map)
{
	return 0;
}
int wc_ecc_mulmod_ex_org(mp_int* k,ecc_point * G,ecc_point * R,mp_int* a,mp_int* modulus,int map,void* heap)
{
	return 0;
}
int wc_ecc_export_x963_org(ecc_key* key,byte* out,word32* outLen)
{
	return 0;
}
int wc_ecc_export_x963_ex_org(ecc_key* key,byte* out,word32* outLen,int compressed)
{
	return 0;
}
int wc_ecc_import_x963_org(const byte* in,word32 inLen,ecc_key* key)
{
	return 0;
}
int wc_ecc_import_x963_ex_org(const byte* in,word32 inLen,ecc_key* key,int curve_id)
{
	return 0;
}
int wc_ecc_import_private_key_org(const byte* priv,word32 privSz,const byte* pub,word32 pubSz,ecc_key* key)
{
	return 0;
}
int wc_ecc_import_private_key_ex_org(const byte* priv,word32 privSz,const byte* pub,word32 pubSz,ecc_key* key,int curve_id)
{
	return 0;
}
int wc_ecc_rs_to_sig_org(const char* r,const char* s,byte* out,word32* outlen)
{
	return 0;
}
int wc_ecc_sig_to_rs_org(const byte* sig,word32 sigLen,byte* r,word32* rLen,byte* s,word32* sLen)
{
	return 0;
}
int wc_ecc_import_raw_org(ecc_key* key,const char* qx,const char* qy,const char* d,const char* curveName)
{
	return 0;
}
int wc_ecc_import_raw_ex_org(ecc_key* key,const char* qx,const char* qy,const char* d,int curve_id)
{
	return 0;
}
int wc_ecc_export_private_only_org(ecc_key* key,byte* out,word32* outLen)
{
	return 0;
}
int wc_ecc_export_public_raw_org(ecc_key* key,byte* qx,word32* qxLen,byte* qy,word32* qyLen)
{
	return 0;
}
int wc_ecc_export_private_raw_org(ecc_key* key,byte* qx,word32* qxLen,byte* qy,word32* qyLen,byte* d,word32* dLen)
{
	return 0;
}
int wc_ecc_export_point_der_org(const int curve_idx,ecc_point* point,byte* out,word32* outLen)
{
	return 0;
}
int wc_ecc_import_point_der_org(byte* in,word32 inLen,const int curve_idx,ecc_point* point)
{
	return 0;
}
int wc_ecc_sig_size_org(ecc_key* key)
{
	return 0;
}
//END DEC_ALL

int wc_ecc_size_org(ecc_key*  key)
{
	return 28;
}

int wc_ecc_get_oid_org(word32 oidSum, const byte* *  oid, word32*  oidSz)
{
	if(oidSz) *oidSz = 10;
	return 0;
}

