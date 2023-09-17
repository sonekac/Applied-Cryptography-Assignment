#include <openssl/sha.h>
#include <string.h>
#include <stdint.h>
#include "utils.h"
//////////////////////////////////////////////////////////////////////
//																	//
//  This program provides the functions to encrypt, decrypt and     //
//  create s-boxes, according to the E-DES version proposed in 		//
//	the assigment													//
// 																	//
//////////////////////////////////////////////////////////////////////
// The static variable BLOCKSIZE32 is the amount uint32_t values 
// to define 1 block
const int BLOCKSIZE32 = 2;
// The static variable NUMBERSBOXES is the number s-boxes needed in 
// the set values
const int NUMBERSBOXES = 16;
// The static variable SBOXESIZE is the size of the s-boxes
const int SBOXESIZE = 32;
/*
This function receives a plaintext block and set of s-boxes, applies the 
Feistel Network, output the ciphered text to the output argument.
Arguments:
	plaintext: one of the uint8_t arrays to apply the operator
	sbox_list: one of the uint8_t arrays to apply the operator
	output: output argument for the ciphered text
*/
uint32_t* Feistel_NetworkCipher(uint32_t plaintext[BLOCKSIZE32],
							    uint8_t sbox_list[NUMBERSBOXES][SBOXESIZE],
							    uint32_t output[BLOCKSIZE32])
{
	output[0] = plaintext[0];
	output[1] = plaintext[1];
	uint32_t interm;
	uint32_t interm1;
	uint8_t in [4];
	uint8_t out [4];
	int index;

	for (int i = 0; i < NUMBERSBOXES; ++i)
	{
		in[3] = (output[1]) ;
		in[2] = (output[1] >> 8);
		in[1] = (output[1] >> 16);
		in[0] = (output[1] >> 24);

		index = in [0];
		out [3] = sbox_list[i][ index ];

		index = ( index + in [1]) % SBOXESIZE;
		out [2] = sbox_list[i][ index ];

		index = ( index + in [2]) % SBOXESIZE;
		out [1] = sbox_list[i][ index ];

		index = ( index + in [3]) % SBOXESIZE;
		out [0] = sbox_list[i][ index ];
		
		interm1 = output[1];
		interm = (out[0] << 24 | out[1] << 16 |
				  out[2] << 8 | out[3]);
		output[1] = interm ^ output[0];
		output[0] = interm1;
		
	}

	return output;

}
/*
This function receives a ciphertext block and set of s-boxes, applies the 
reverse Feistel Network, outputs the plain text to the output argument.
Arguments:
	ciphertext: one of the uint8_t arrays to apply the operator
	sbox_list: one of the uint8_t arrays to apply the operator
	output: output argument for the plaintext
*/
uint32_t* Feistel_NetworkDecipher(uint32_t ciphertext[BLOCKSIZE32],
						  uint8_t sbox_list[NUMBERSBOXES][SBOXESIZE],
						  uint32_t output[BLOCKSIZE32])
{
	output[0] = ciphertext[1];
	output[1] = ciphertext[0];
	uint32_t interm;
	uint32_t interm1;
	uint8_t in [4];
	uint8_t out [4];
	int index;

	for (int i = 15; i >= 0; --i)
	{
		in[3] = (output[1]) ;
		in[2] = (output[1] >> 8);
		in[1] = (output[1] >> 16);
		in[0] = (output[1] >> 24);

		index = in [0];
		out [3] = sbox_list[i][ index ];

		index = ( index + in [1]) % SBOXESIZE;
		out [2] = sbox_list[i][ index ];

		index = ( index + in [2]) % SBOXESIZE;
		out [1] = sbox_list[i][ index ];

		index = ( index + in [3]) % SBOXESIZE;
		out [0] = sbox_list[i][ index ];
		
		interm1 = output[1];
		interm = (out[0] << 24 | out[1] << 16 |
				  out[2] << 8 | out[3]);
		output[1] = interm ^ output[0];
		output[0] = interm1;
		
	}
	interm1 = output[0];

	output[0] = output[1];

	output[1] = interm1;

	return output;

}
/*
This function receives a plaintext block and set of s-boxes, applies the 
Feistel Network, output the ciphered text to the output argument.
Arguments:
	plaintext: one of the uint8_t arrays to apply the operator
	sbox_list: one of the uint8_t arrays to apply the operator
	output: output argument for the ciphered text
*/
void encrypt(uint32_t plaintext[BLOCKSIZE32],
			 uint8_t sbox_list[NUMBERSBOXES][SBOXESIZE],
			 uint32_t output[BLOCKSIZE32])
{
	output = Feistel_NetworkCipher(plaintext, sbox_list, output);
}
/*
This function receives a ciphertext block and set of s-boxes, applies the 
reverse Feistel Network, outputs the plain text to the output argument.
Arguments:
	ciphertext: one of the uint8_t arrays to apply the operator
	sbox_list: one of the uint8_t arrays to apply the operator
	output: output argument for the plaintext
*/
void decrypt(uint32_t* ciphertext, 
			 uint8_t sbox_list[NUMBERSBOXES][SBOXESIZE],
			 uint32_t output[BLOCKSIZE32])
{
	output = Feistel_NetworkDecipher(ciphertext, sbox_list, output);
}
/*
This function applies Linear Feed Back Registry on an array
Arguments:
	pivot: an uint8_t array where lfsr is applied and returned
*/
void lfsr(uint8_t pivot[SBOXESIZE])
{
	uint8_t unchanged[29];
	subarray8bits( pivot, 0, 30, unchanged);
	uint8_t changed[3];

	uint8_t section1[3];
	subarray8bits(pivot, 0, 4, section1);
	uint8_t section2[3];
	subarray8bits(pivot, 10, 14, section2);
	uint8_t section3[3]; 
	subarray8bits(pivot, 20, 24, section3);

	XOR8bitsarray(changed, section1, section2, section3, 3);

	mergea8bitrray(changed, 3,unchanged, 29, pivot);

}
/*
This function receives a subkey and converts it to a 2048 bit digest 
without any duplicate. 
Arguments:
	subkey: an array of uint8_t to base the digest
	digest: 2048 bit digest without any duplicate
*/
void generate_digest2048(uint8_t* subkey, uint8_t digest[SBOXESIZE])
{
	memset(digest, 0, SBOXESIZE);

	uint8_t subdigest_array[8][SBOXESIZE];
	SHA256(subkey, sizeof(subkey), subdigest_array[0]);

	for (int i = 0; i < 7; ++i)
	{
		SHA256(subdigest_array[i], sizeof(subdigest_array[i]), 
			   subdigest_array[i + 1]);
	}

	uint8_t counter = 0;
	int j = 0;
	int position = 0;
	for (int k = 0; k < 8; ++k)
	{
		for (int i = 0; i < SBOXESIZE; ++i)
		{
			j = subdigest_array[k][i];
			for (int t = 0; t < SBOXESIZE; ++t)
			{
				position = j%SBOXESIZE;
				if (digest[position] == 0)
				{
					digest[position] = counter;
					counter++;
					break;
				}
				else
				{
					j++;
				}

			}
		} 
	}
}
/*
This function receives a digest and converts it to a 256 bit digest 
without any duplicate. 
Arguments:
	digest: an array of uint8_t to base the digest
	sbox: 256 bit digest without any duplicate
*/
void generate_digest256_nodup(uint8_t digest[SBOXESIZE], 
							  uint8_t sbox[SBOXESIZE])
{
	memset(sbox, 0, SBOXESIZE);

	uint8_t counter = 0;
	int j = 0;
	int position = 0;
	for (int i = 0; i < SBOXESIZE; ++i)
	{
		j = digest[i];
		for (int t = 0; t < SBOXESIZE; ++t)
		{
			position = j%SBOXESIZE;
			if (sbox[position] == 0)
			{
				sbox[position] = counter;
				counter++;
				break;
			}
			else
			{
				j++;
			}

		}
	} 
}
/*
This function receives a key, breaks it into 3 subkeys and creates a 
digest from each subkey. With the 3 digests we create pseudo-random
generator, that will generate each s-boxes.
Arguments:
	key: key to generate s-boxes from
	s-boxes: the resulting set of s-boxes 
*/
void sbox_generator(unsigned char key[SBOXESIZE], 
					uint8_t s_boxes[NUMBERSBOXES][SBOXESIZE])
{
	uint8_t digest1[SBOXESIZE];
	uint8_t digest2[SBOXESIZE];
	uint8_t digest3[SBOXESIZE];
	uint8_t digest[SBOXESIZE];

	uint8_t substring1[10];
	uint8_t substring2[10];
	uint8_t substring3[12];

	subarray8bits(key, 0, 10, substring1);
	subarray8bits(key, 10, 20, substring2);
	subarray8bits(key, 20, 32, substring3);

	generate_digest2048(substring1, digest1);
	generate_digest2048(substring2, digest2);
	generate_digest2048(substring3, digest3);

	for(int i = 0; i < NUMBERSBOXES; i++)
	{
		if (i % 3 == 1)
		{
			lfsr(digest1);
			lfsr(digest2);
		}
		if (i % 3 == 2)
		{
			lfsr(digest2);
			lfsr(digest3);
		}
		if (i % 3 == 0)
		{			
			lfsr(digest3);
			lfsr(digest1);
		}

		XOR8bitsarray(digest, digest1, digest2, digest3, SBOXESIZE);
		generate_digest256_nodup(digest, s_boxes[i]);
	}
}