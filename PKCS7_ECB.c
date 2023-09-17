#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <math.h>
#include <openssl/sha.h>
#include "E-DES.h"
//////////////////////////////////////////////////////////////////////
//																	//
//  This program intends to receive a plaintext message and a key,  //
//  using the key to create the s-boxes and use PKCS #7 for the  	//
//  padding the messages. The program executes every step of  		//
//  encrypting and decrypting, all while displaying the states the 	//
//	message takes.													//
// 																	//
//////////////////////////////////////////////////////////////////////

// The static variable BLOCKSIZECHAR is the amount char values 
// to define 1 block 
const int BLOCKSIZECHAR= 8;
// The static variable BLOCKSIZE is the amount uint32_t values 
// to define 1 block
const int BLOCKSIZE= 2;

/*
PKCS7_padding is function that receives plaintext block, 
in char* (String) format, and ensures that the block according to 
PKCS7, and converts it to an array of uint32_t.
Arguments:
	plaintext: it's a block of plaintext, to be PKCS7 padded
	paddedblock: it's PKCS7 padded of the plaintext 
*/
void PKCS7_padding(char plaintext[], uint32_t paddedblock[BLOCKSIZE])
{
	int plaintext_size = strlen(plaintext);
	if(plaintext_size == BLOCKSIZECHAR)
	{
		paddedblock[0] = (plaintext[0] << 24 | plaintext[1] << 16 | 
						  plaintext[2] << 8 | plaintext[3]);
		paddedblock[1] = (plaintext[4] << 24 | plaintext[5] << 16 | 
						  plaintext[6] << 8 | plaintext[7]);
	}
	else
	{
		int pad_needed = BLOCKSIZECHAR - plaintext_size;
		char padding_value = pad_needed + '0';

		if (plaintext_size < BLOCKSIZECHAR/2)
		{
			int counter = 16;
			paddedblock[0] = (plaintext[0] << 24);
			for (int i = 1; i < plaintext_size; ++i)
			{
				paddedblock[0] = (paddedblock[0] |
								  plaintext[i] << counter );
				counter = counter - 8;
			}

			for (int i = counter; i >= 0 ; i = i - 8)
			{
				paddedblock[0] = (paddedblock[0] |
								  padding_value << i );
			}
		
			paddedblock[1] = (padding_value << 24 | 
							  padding_value << 16 | 
							  padding_value << 8 | 
							  padding_value);

		}
		if (plaintext_size == BLOCKSIZECHAR/2)
		{

			paddedblock[0] = (plaintext[0] << 24 | 
							  plaintext[1] << 16 |
							  plaintext[2] << 8 |
							  plaintext[3]);
			paddedblock[1] = (padding_value << 24 |
							  padding_value << 16 |
							  padding_value << 8 | 
							  padding_value);
		}
		if (plaintext_size > BLOCKSIZECHAR/2)
		{

			paddedblock[0] = (plaintext[0] << 24 |
							  plaintext[1] << 16 | 
							  plaintext[2] << 8 | 
							  plaintext[3]);

			int counter = 16;
			paddedblock[1] = (plaintext[4] << 24);

			for (int i = 5; i < plaintext_size; ++i)
			{
				paddedblock[1] = (paddedblock[1] |
								  plaintext[i] << counter );
				counter = counter - 8;
			}

			for (int i = counter; i >= 0 ; i = i - 8)
			{
				paddedblock[1] = (paddedblock[1] |
				                  padding_value << i );
			}

		}
	}
}
/*
PKCS7_unpadding is function that receives paddedblock, in uint32_t 
array, and converts the block from PKCS7 to char* (String).
Arguments:
	paddedblock: it's PKCS7 padded of the plaintext to be PKCS7 padded.
	plaintext: it's a block of plaintext.
*/
int PKCS7_unpadding(uint32_t paddedblock[BLOCKSIZE], char plaintext[], 
					int j)
{
	unsigned char paddedtext[8];
	paddedtext[0] = paddedblock[0] >> 24;
    paddedtext[1] = paddedblock[0] >> 16;
    paddedtext[2] = paddedblock[0] >> 8;
    paddedtext[3] = paddedblock[0];

    paddedtext[4] = paddedblock[1] >> 24;
    paddedtext[5] = paddedblock[1] >> 16;
    paddedtext[6] = paddedblock[1] >> 8;
    paddedtext[7] = paddedblock[1];


    int padding_value;
    char tmp = (char)paddedtext[7];
    sscanf(&tmp, "%1d", &padding_value);
    padding_value = padding_value;
    bool has_padding = true;

    if(padding_value > 0 && padding_value < 8)
    {
    	for (int i = 6; i >= BLOCKSIZECHAR - padding_value; --i)
    	{
    		if (paddedtext[i] != paddedtext[7])
    		{ 
    			has_padding = false;
    		}
    	}

    	if (has_padding)
    	{
    		for (int i = 0; i < BLOCKSIZECHAR - padding_value; ++i)
    		{
    			plaintext[j] = (char)paddedtext[i];
    			j++;
    		}
    	}
    	else
	    {
	    	for (int i = 0; i < BLOCKSIZECHAR; ++i)
			{
				plaintext[j] = (char)paddedtext[i];
				j++;
			}
	    }
    }
    else
    {
    	for (int i = 0; i < BLOCKSIZECHAR; ++i)
		{
			plaintext[j] = (char)paddedtext[i];
			j++;
		}
    }

    return j;
}
/*
E_DES function receives a key(String) and plaintext(String), it
encrypts and decrypts with PKCS #7: Cryptographic Message Syntax, 
showing the message states in standout.
Arguments:
	plaintext: its a plaintext message to be ciphered.
	key: a key to generate the s-boxes of E-DES Algorithm.
*/
void E_DES(char* plaintext, char* key)
{
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

  	printf("\nDeciphered plaintext:\n%s\n", decipheredtext);
	
}

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
	E_DES(argv[1], argv[2]);
	return 1;	
}