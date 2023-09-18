#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
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