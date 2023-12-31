#include <stdint.h>

void encrypt(uint32_t* plaintext, uint8_t sbox_list[16][256],
			 uint32_t output[2]);

void decrypt(uint32_t* ciphertext, uint8_t sbox_list[16][256],
			 uint32_t output[2]);

void substring(unsigned char* src, int start, int end, 
			   unsigned char* sub);

void sbox_generator(unsigned char* key, uint8_t s_boxes[16][256]);
