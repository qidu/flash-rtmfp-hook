#define NOMINMAX

#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <detours.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <stdint.h>
#include <algorithm>

#include "mybuffer.h"


#pragma comment( lib, "detours.lib" )
FILE* logfile;

/** 12个月份的缩写 */
const char* monthStr[]={"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug","Sep", "Oct", "Nov", "Dec"};



/**
 * @param type 日志的类型，可以是任何字符串，不含双引号
 * @param data 日志的内容
 */
static void logToFile(const std::string& type, const std::string& data)
{

	SYSTEMTIME st, lt;
	GetSystemTime(&st);	
	GetLocalTime(&lt);	
	std::ostringstream oss;	
	oss<<"{time:\""<<monthStr[lt.wMonth-1]<<" "<<lt.wDay<<", "<<lt.wYear<<" "<<lt.wHour<<":"<<lt.wMinute<<":"<<lt.wSecond<<"."<<lt.wMilliseconds<<"\"";
	oss<<",type: \""<<type<<"\",data: {"<<data<<"}}\n";
	std::string msg=oss.str();
	fwrite(msg.c_str(),1,msg.length(),logfile);
	fflush(logfile);
}

/**
 * 打开日志文件
 * @filename
 */
void initLogFile(const char* filename){
	logfile=fopen(filename,"a+");	
}

/**
 * 关闭日志文件 
 */
void closeLogFile(){	
	if(logfile!=NULL)
		fclose(logfile);
}

/*
static char hexchar(uint8_t value){
	static char str[]="0123456789abcdef";
	if(value>=16) throw std::runtime_error("internal error");
	return str[value];
}

static std::string hexBuffer(const uint8_t* buff,int length){
	std::ostringstream oss;
	oss<<std::hex<<std::uppercase;
	oss<<"\"";
	for(int i=0;i!=length;++i)
		oss<<hexchar(buff[i]>>4)<<hexchar(buff[i]&0xF);
	oss<<"\"";
	return oss.str();
}*/

static std::string jsonArray(const uint8_t* buff,int length){
	std::ostringstream oss;
	oss<<"[";
	for(int i=0;i!=length;++i){
		oss<<(uint32_t)buff[i];
		if(i!=length-1)
			oss<<",";
	}
	oss<<"]";
	return oss.str();
}


//only used for detours inject
__declspec(dllexport) void __cdecl dummyfunc(void){

}

char  (__fastcall *oldfunc)(void* pthis,int dummy,const unsigned char *key, int keyType, int direction)=(char  (__fastcall *)(void* pthis,int dummy,const unsigned char *key, int keyType, int direction))0x7AE1E1;


/**
 * CCMEAESContext
 */
class C00B4F258{
public:		
	char newfunc(const unsigned char *key, int keyType, int direction){
		size_t keylength;
		if ( keyType )
		{
			if ( keyType == 1 )
			{
				keylength = 192;
			}
			else
			{
				if ( keyType != 2 )
					return 0;
				keylength = 256;
			}
		}
		else
		{
			keylength = 128;
		}
		keylength=keylength/8;
		std::ostringstream oss;
		oss<<"key: "<<jsonArray(key,keylength)<<",direction:"<<direction;
		logToFile("keyinfo",oss.str());	
		char ret=oldfunc(this,0,key,keyType,direction);		
		return ret;
	}
};



char (__fastcall  *oldfunc7A6807)(void* pthis,int dummy,char *dhpublicnumber, unsigned int length)=
	(char (__fastcall*)(void* pthis,int dummy,char *dhpublicnumber, unsigned int length))0x007A6807;
	
class C00B4C8E8{
public:
	int vtable;
	int ref;
	int unknown1;
	MyBuffer b1;
	MyBuffer b2;
	MyBuffer b3;
	MyBuffer b4;

	/*
	 char func7A6807(char *dhpublicnumber, unsigned int length){
		int ret=oldfunc7A6807(this,0,dhpublicnumber,length);
		std::ostringstream oss;
		oss<<"{type: \"dhinfo\",data: {b4:"<<hexBuffer(this->b4.data,this->b4.length)<<"}}";
		std::string msg=oss.str();
		logToFile(msg.c_str());
		return ret;
	 }*/
};

int (__fastcall  *oldfunc7A17EA)(void* pthis,int dummy,uint8_t *dhpublicnumber, int length, int keyType)=
	(int (__fastcall  *)(void* pthis,int dummy,uint8_t *dhpublicnumber, int length, int keyType))0x007A17EA;


/**
 * RTMFP::CCMECryptoKey
 */
class C00B4C820{
public:
	int vtable;
	int ref;
	C00B4F258* key1;
	C00B4F258* key2;
	C00B4C8E8* info;
	int unknown1;
	int unknown2;
	int unknown3;
	int unknown4;
	int unknown5;
	int unknown6;
	int unknown7;
	int unknown8;
	int unknown9;
	int unknown10;
	int unknown11;
	int unknown12;
	int unknown13;
	MyBuffer* initiatorNonce;
	MyBuffer* responderNonce;
	uint8_t nearNonce[0x20];
	uint8_t farNonce[0x20];
	

	char func007A17EA(uint8_t *dhpublicnumber, int length, int keyType){
		std::ostringstream oss;
		oss<<"dhpublicnumber:"<<jsonArray(dhpublicnumber,length)
		<<",initiatorCert:"<<jsonArray(this->initiatorNonce->data,this->initiatorNonce->length)
		<<",responderCert:"<<jsonArray(this->responderNonce->data,this->responderNonce->length)
		<<",dhprime:"<<jsonArray(this->info->b1.data,this->info->b1.length)
		<<",dhprivatekey:"<<jsonArray(this->info->b2.data,this->info->b2.length);
		char ret=oldfunc7A17EA(this,0,dhpublicnumber,length,keyType);
		oss<<",farNonce:"<<jsonArray(this->farNonce,sizeof(this->farNonce))
			<<",nearNonce:"<<jsonArray(this->nearNonce,sizeof(this->nearNonce));
		std::string msg=oss.str();
		logToFile("secinfo",msg.c_str());
		
		return ret;
	}
};

/**
 * 地址信息
 */
class C00AFE190{
public:
	int vtable;
	void* unknown1;
	char buffer[0x80];
	int addrlen;
};

int (__fastcall  *oldfunc5DCFFE)(void* pthis,int dummy,uint8_t *buf, int len, C00AFE190* a4)=
	(int (__fastcall *)(void* pthis,int dummy,uint8_t *buf, int len, C00AFE190* a4))0x005DCFFE;

int (__fastcall  *oldfunc5DD07D)(void* pthis,int dummy,uint8_t *buf, int len, C00AFE190* a4)=
	(int (__fastcall *)(void* pthis,int dummy,uint8_t *buf, int len, C00AFE190* a4))0x005DD07D;

int (__fastcall  *oldfunc5DD293)(void* pthis,int dummy,uint8_t *buf, int len, int port, int addressFamily)=
	(int (__fastcall *)(void* pthis,int dummy,uint8_t *buf, int len, int port, int addressFamily))0x005DD293;


void logerror(const char* file,long line,const std::string& msg){
	std::ostringstream oss;
	oss<<"error:\""<<msg<<"\",file: \""<<file<<"\",line: "<<line;
	std::string err=oss.str();
	logToFile("error",err.c_str());
}

#define LOG_ERROR(msg) {logerror(__FILE__,__LINE__,msg);}

/**
 * 网络管理器
 */
class C00B0C408{
	int vtable;
	int ref;
	int socket;
public:	
	int func5DD293(uint8_t *buf, int len, int port, int addressFamily){
		std::ostringstream oss;		
		oss<<"socket:"<<this->socket<<",port:"<<port<<",addressFamily:"<<addressFamily<<",data: "<<jsonArray(buf,len);		
		std::string msg=oss.str();
		logToFile("send2",msg);
		return oldfunc5DD293(this,0,buf,len,port,addressFamily);
	}

	int func5DD07D(uint8_t *buf, int len, C00AFE190* a4){
		sockaddr* addr=(sockaddr*)a4->buffer;
		char ipstringbuffer[128];
		DWORD ipstringbufferLength=128;
		WSAAddressToStringA(addr,a4->addrlen,NULL,ipstringbuffer,&ipstringbufferLength);
		std::ostringstream oss;			
		oss<<"socket:"<<this->socket<<",addr:\""<<ipstringbuffer<<"\",data: "<<jsonArray(buf,len);				
		logToFile("send",oss.str());
		return oldfunc5DD07D(this,0,buf,len,a4);
	}	
	int func5DCFFE(uint8_t *buf, int len, C00AFE190* a4){
		int ret=oldfunc5DCFFE(this,0,buf,len,a4);	
		if(ret>0){
			sockaddr* addr=(sockaddr*)a4->buffer;
			char ipstringbuffer[128];
			DWORD ipstringbufferLength=128;
			WSAAddressToStringA(addr,a4->addrlen,NULL,ipstringbuffer,&ipstringbufferLength);
			std::ostringstream oss;
			oss<<"socket:"<<this->socket<<",addr:\""<<ipstringbuffer<<"\",data: "<<jsonArray(buf,ret);	
			logToFile("recv",oss.str());			
		}
		return ret;
	}
};




static void doRegister(){
	LONG error;
	DetourTransactionBegin();
	DetourUpdateThread( GetCurrentThread() );

	//记录key
	DetourAttach( &(PVOID &)oldfunc,(PVOID)(&(PVOID&) C00B4F258::newfunc));
	
	//计算AES key
	DetourAttach( &(PVOID &)oldfunc7A17EA,(PVOID)(&(PVOID&) C00B4C820::func007A17EA));	
	//发送局域网UDP广播
	DetourAttach( &(PVOID &)oldfunc5DD293,(PVOID)(&(PVOID&) C00B0C408::func5DD293));	
	//收到UDP包
	DetourAttach( &(PVOID &)oldfunc5DCFFE,(PVOID)(&(PVOID&) C00B0C408::func5DCFFE));	
	//发送UDP包
	DetourAttach( &(PVOID &)oldfunc5DD07D,(PVOID)(&(PVOID&) C00B0C408::func5DD07D));		
	error=DetourTransactionCommit(); 
	if(error==NO_ERROR){
		logToFile("begin","");
	}
}

static void doUnRegister(){
	LONG error;
	DetourTransactionBegin();
	DetourUpdateThread( GetCurrentThread() );
	//DetourDetach( &(PVOID &)oldfunc7A6807,(PVOID)(&(PVOID&) C00B4C8E8::func7A6807));
	DetourDetach( &(PVOID &)oldfunc7A17EA,(PVOID)(&(PVOID&) C00B4C820::func007A17EA));	
	DetourDetach( &(PVOID &)oldfunc5DD293,(PVOID)(&(PVOID&) C00B0C408::func5DD293));	
	DetourDetach( &(PVOID &)oldfunc5DCFFE,(PVOID)(&(PVOID&) C00B0C408::func5DCFFE));	
	DetourDetach( &(PVOID &)oldfunc5DD07D,(PVOID)(&(PVOID&) C00B0C408::func5DD07D));	
	DetourDetach( &(PVOID &)oldfunc,(PVOID)(&(PVOID&) C00B4F258::newfunc));
	error=DetourTransactionCommit(); 
	logToFile("end","");
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{	
	
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		initLogFile("flash.log");		
		doRegister();
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		doUnRegister();
		closeLogFile();
		break;
	}
	return TRUE;
}

