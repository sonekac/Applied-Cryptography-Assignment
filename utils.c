#include <stdio.h>
#include <string.h>
#include <stdint.h>
//////////////////////////////////////////////////////////////////////
//																	//
//  This is a collection of a general purposed functions to			//
//  support the main program.									  	//
// 																	//
//////////////////////////////////////////////////////////////////////

/*
This function receives string and the expected string size, and prints
the string in hexadecimal readable format.
Arguments:
	src: char array to be printed in hexadecimal
	size: string size to be printed
*/
void print(unsigned char* src, int size)
{
	for (int i = 0; i < size; ++i)
	{
		printf("%X ", src[i]);
	}
}

/*
This function receives as arguments the string(src), the start(start) 
and end(end) of the substring to be extracted, and an output 
variable(sub).
Arguments:
	src: char array to be extracted a substring
	start: the index of the start of the substring
	end: the index of the end of the substring
	sub: output argument for the resulting substring
*/
void substring(unsigned char* src, int start, int end,
			   unsigned char* sub)
{
 	int j = 0;

    for (int i = start; i < end ; ++i)
    {
        memcpy(&sub[j], &src[i],1);
        j++;
    }
    sub[j] = '\0';
}
/*
This function receives as arguments the uint8_t(src), the start(start) 
and end(end) of the substring to be extracted, and an output 
variable(sub).
Arguments:
	src: uint8_t array to be extracted a subarray
	start: the index of the start of the subarray
	end: the index of the end of the subarray
	sub: output argument for the resulting subarray
*/
void subarray8bits(uint8_t* src, int start, int end, uint8_t* sub)
{
 	int j = 0;

    for (int i = start; i < end ; ++i)
    {
    	memcpy(&sub[j], &src[i],1);
        j++;
    }
}

/*
This function receives as arguments 3 uint8_t arrays, and applies XOR 
function, and outputs to the variable output.
Arguments:
	str1: one of the uint8_t arrays to apply the operator
	str2: one of the uint8_t arrays to apply the operator
	str3: one of the uint8_t arrays to apply the operator
	size: size of the strings to applied the XOR operation
	output: output argument
*/
void XOR8bitsarray(uint8_t* output, uint8_t* str1, uint8_t* str2,
				   uint8_t* str3, int size)
{
	
	for (int i = 0; i < size; ++i)
	{
		output[i] = str1[i] ^ str2[i];
		output[i] = output[i] ^ str3[i];
	}
}
/*
This function receives as arguments 2 uint8_t arrays, and merges them
to a single array, and outputs to the argument dest.
Arguments:
	src1: one of the uint8_t arrays to merge
	size1: size of the src1
	src2: one of the uint8_t arrays to merge
	size2: size of the src2 
	output: output argument
*/
void mergea8bitrray(uint8_t src1[], int size1, uint8_t src2[],
				    int size2, uint8_t* dest)
{
	for (int i = 0; i < size1 + size2; ++i)
	{
		if (i < size1)
		{
			memcpy(&dest[i], &src1[i],1);
		}
		else
		{
			memcpy(&dest[i], &src2[i - size1],1);
		}
	}
}