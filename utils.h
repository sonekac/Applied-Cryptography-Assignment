#include <stdint.h>

void print(unsigned char* src, int size);

void substring(unsigned char* src, int start, int end,
			   unsigned char* sub);

void subarray8bits(uint8_t* src, int start, int end, uint8_t* sub);

void XOR3Strings(unsigned char* output, unsigned char* str1, int size,
				 unsigned char* str2, unsigned char* str3);

void XOR8bitsarray(uint8_t* output, uint8_t* str1, uint8_t* str2,
				   uint8_t* str3, int size);

void mergea8bitrray(uint8_t src1[], int size1, uint8_t src2[],
				    int size2, uint8_t* dest);