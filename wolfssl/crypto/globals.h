#ifndef globals_h
#define globals_h
#define _IS(X) strcmp(input, X"\n") == 0
#define eprintf(M, G) {fprintf(stderr, "[Error][%s] %s ", __func__, M); goto G;}

#define MAX_INPUT 10
#define MAX_NON_BLOCK_SEC   60
#define CERT_DET_LEN 2000
#define BUFF_SIZE 4096
#define IP_BUFF_SIZE 100
#define RESPONSE_SIZE 15001
#define HTTPS_PORT 443

typedef enum {
	ENC_RSA = 1,
	ENC_ECC,
	ENC_NONE
} pub_key_enc_t;

typedef enum {
	VERIFY_OVERRIDE_ERROR,
	VERIFY_FORCE_FAIL,
	VERIFY_USE_PREVERFIY,
	VERIFY_OVERRIDE_DATE_ERR,
	VERIFY_NONE
} VRF_ACTION_T;


#endif