#pragma once
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdexcept>

extern int readVarInt64(const uint8_t *beginptr, uint64_t * outvalue, const uint8_t *endptr);
extern int readVarInt32(const uint8_t *a1, uint32_t* a2, const uint8_t *a3);
extern int readVarLength(uint8_t *buffer, uint32_t *outVar, uint8_t *bufferEnd);


class MyBuffer {
public:
	int vtable;
	int unknown;
	uint8_t *data;
	int length;
	int pos;
	char flags;

	/** from decompiler*/
	MyBuffer(uint8_t* data,int dataLength,char flags=0){
		this->flags &= 0xF8u;
		this->data=0;
		this->vtable =0xB4C8E0;
		this->length=0;
		this->pos=0;
		if(!this->initdata(data,dataLength,flags))
			throw std::runtime_error("init data fail");
	}

	uint8_t* getCurrentPtr(){
		return data+pos;
	}


	int getRemain(){
		return length-pos;
	}
	uint8_t* getEndPtr(){
		return data+length;
	}

	bool isEof(){
		return getCurrentPtr()<getEndPtr();
	}

	template <typename T>
	T readInt(){
		int newpos=pos+sizeof(T);
		if(newpos>length)
			throw std::runtime_error("eof exception");
		T ret=*(T*)getCurrentPtr();
		pos=newpos;
		return ret;
	}
	int readVarInt64(uint64_t * outvalue){
		int ret=::readVarInt64(data+pos,outvalue,data+length);
		if(ret)
			pos+=ret;
		return ret;
	}

	int readVarInt32(uint32_t * outvalue){
		int ret=::readVarInt32(data+pos,outvalue,data+length);
		if(ret)
			pos+=ret;
		return ret;
	}

	MyBuffer readVarData(){
		uint32_t size;
		int l=::readVarLength(data+pos,&size,data+length);
		if(l<=0)
			throw std::runtime_error("read var data error");
		pos+=l;
		auto begin=getCurrentPtr();
		pos+=size;
		return MyBuffer(begin,size,0);		
	}

	/** from decompiler*/
	~MyBuffer() throw (){
		if(this->flags & 1)
			free(this->data);
	}

	/** from decompiler*/
	char  initdata(void *data, int dataLength, char flags)
	{
		uint8_t *v6; 		
		if ( this->data )
			return 0;
		if ( flags & 1 && !data )
			return 0;
		this->pos = 0;
		this->length = dataLength;
		if ( data && flags & 1 )
		{
			this->data = (uint8_t *)data;
		}
		else
		{
			v6 = (uint8_t *)calloc(1u, dataLength);
			this->data = v6;
			if ( !v6 )
				return 0;
			this->flags |= 3u;
			if ( data )
				memcpy(v6, data, dataLength);
		}
		if ( flags & 2 )
			this->flags |= 1u;
		if ( flags & 4 )
			this->flags |= 2u;
		if ( flags & 8 )
			this->flags |= 4u;
		return 1;
	}

};