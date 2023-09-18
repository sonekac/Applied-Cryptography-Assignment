#include <stdint.h>

void PKCS7_padding(char plaintext[], uint32_t paddedblock[]);

int PKCS7_unpadding(uint32_t paddedblock[], char plaintext[], 
					int j);

void E_DES(char* plaintext, char* key);

