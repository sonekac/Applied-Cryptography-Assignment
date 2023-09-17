#include <stdint.h>

// The static variable BLOCKSIZE32 is the amount uint32_t values 
// to define 1 block
const int BLOCKSIZE32 = 2;
// The static variable NUMBERSBOXES is the number s-boxes needed in 
// the set values
const int NUMBERSBOXES = 16;
// The static variable SBOXESIZE is the size of the s-boxes
const int SBOXESIZE = 32;

void encrypt(uint32_t* plaintext, uint8_t sbox_list[16][256],
			 uint32_t output[2]);

void decrypt(uint32_t* ciphertext, uint8_t sbox_list[16][256],
			 uint32_t output[2]);

void substring(unsigned char* src, int start, int end, 
			   unsigned char* sub);

void sbox_generator(unsigned char* key, uint8_t s_boxes[16][256]);
