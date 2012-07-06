#include "mybuffer.h"


size_t  write7bitInt(uint64_t value, void *dest){
	uint64_t v2; 
	size_t v3;
	signed int v4;
	char source[12]; 

	v2 = value;
	v3 = 0;
	v4 = 10;
	do
	{
		--v4;

		if ( v3 )
			source[v4] = v2 & 0x7F | 0x80;
		else 
			source[v4] = v2 & 0x7F;
		v2 >>= 7;		
		++v3;
	}
	while ( v2 && v3 < 10 );
	if ( dest )
		memmove(dest, &source[v4], v3);
	return v3;
}

// 往outVar中写入读到的值。return读了多少个字节
int  readVarLength(uint8_t *buffer, uint32_t *outVar, uint8_t *bufferEnd)
{
	uint8_t *v3; 
	int result; 
	uint32_t value;
	v3 = bufferEnd;
	if ( bufferEnd
		&& bufferEnd >= buffer
		&& (result = readVarInt32(buffer, &value, bufferEnd)) != 0
		&& value>=0
		&& (int32_t)value <= v3-result - buffer )// 很重要的安全检查！
	{
		if ( outVar )
			*outVar = value;
	}
	else
	{
		result = 0;
	}
	return result;
}


int readVarInt32(const uint8_t *a1, uint32_t* a2, const uint8_t *a3)
{
	int result;
	uint64_t v4; 

	result = readVarInt64(a1, &v4, a3);
	if ( result && a2 )
	{
		if ( v4 <= 0xFFFFFFFF )
			*a2 = (uint32_t)v4;
		else
			*a2 = -1;
	}
	return result;
}


int  readVarInt64(const uint8_t *beginptr, uint64_t * outvalue, const uint8_t *endptr)
{
	int count=0;
	const uint8_t* p = beginptr;
	bool ismax=false;
	uint64_t value=0;
	if ( !p ) {
		return 0;
	} 
	while ( !endptr || p < endptr )
	{
		uint8_t v=*p;
		if ((value >>32) > 0x1FFFFFF)
			ismax=true;

		value = (value<< 7) + (v & 0x7F);
		++count;		
		if ( v <= 127 )
			break;
		++p;
	}
	if ( endptr && p >= endptr )
	{
		count = 0;
	}
	else
	{
		if ( ismax )
		{
			value=(uint64_t)-1;
		}
		if ( outvalue )
		{
			*outvalue=value;
		}		
	}
	return count;
}
