#include <stdio.h>
#include <string.h>
#include <math.h>
#include <openssl/sha.h>
#include "E-DES.h"
#include "PKCS7_ECB.h"
// The static variable BLOCKSIZECHAR is the amount char values 
// to define 1 block 
extern const int BLOCKSIZECHAR;
// The static variable BLOCKSIZE is the amount uint32_t values 
// to define 1 block
extern const int BLOCKSIZE;
/*
The main function is expected to receive 2 arguments, 
a plaintext(on argv[1]) and key(on argv[2]), and calls E_DES function.
Arguments:
	argc: expected to be equal to 3
	argv[1]: its a plaintext message to be applied on E-DES Algorithm.
	argv[2]: its a key message to be applied on E-DES Algorithm.
*/

int main(int argc, char *argv[]) 
{
	printf("Plain Text: %s\n", argv[1]);
	printf("\n");
	printf("Key: %s\n", argv[2]);

	char* plaintext = argv[1];
	char* key = argv[2];

	int key_lineSize = strlen(key);
	int plaintext_lineSize = strlen(plaintext);

  	char key256bits[32];
	SHA256(key, key_lineSize,key256bits);
			
	uint8_t sbox_list[16][256];
	sbox_generator(key256bits, sbox_list);

	int ciphertext_len;
	ciphertext_len = 2 * (1 + ceil(plaintext_lineSize/BLOCKSIZECHAR));

  	uint32_t ciphertext[ciphertext_len]; 
  	uint32_t Intermciphertext[BLOCKSIZE]; 
  	uint32_t plaintext_block[BLOCKSIZE];

  	char pivot[BLOCKSIZECHAR];
  	int j = 0;

  	for (int i = 0; i < plaintext_lineSize; i = BLOCKSIZECHAR + i)
  	{
  		substring(plaintext, i, i + BLOCKSIZECHAR, pivot);
  		PKCS7_padding(pivot, plaintext_block);
  		encrypt(plaintext_block, sbox_list, Intermciphertext);
  		ciphertext[j] = Intermciphertext[0];
  		ciphertext[j + 1] = Intermciphertext[1];

  		j = j + BLOCKSIZE;
  	}

	printf("\nCiphered text: \n");

	for (int i = 0; i < ciphertext_len; ++i)
	{
		printf("%08x ", ciphertext[i]); 
	}
  	printf("\n\n\n");

  	int k = 0;

  	char decipheredtext[plaintext_lineSize];
  	uint32_t Intermpplaintext[BLOCKSIZE];
  	uint32_t ciphertext_block[BLOCKSIZE];

  	for (int i = 0; i < ciphertext_len; i = i + BLOCKSIZE)
  	{
  		ciphertext_block[0] = ciphertext[i];
  		ciphertext_block[1] = ciphertext[i + 1];
  		decrypt(ciphertext_block, sbox_list, Intermpplaintext);
  		k = PKCS7_unpadding(Intermpplaintext, decipheredtext, k);
  	}
  	decipheredtext[plaintext_lineSize] = '\0';
  	printf("\nDeciphered plaintext:\n%s\n", decipheredtext);
	return 1;	
}