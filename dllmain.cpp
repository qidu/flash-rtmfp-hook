#define NOMINMAX
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

static void logToFile(const char* s)
{
	fprintf(logfile, "%s", s);
	fflush(logfile);
}

void initLogFile(const char* filename){
	logfile=fopen(filename,"a+");	
}


void closeLogFile(){	
	if(logfile!=NULL)
		fclose(logfile);
}

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
}

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
/*
char  (__fastcall *oldfunc)(void* pthis,int dummy,const unsigned char *key, int keyType, int direction)=(char  (__fastcall *)(void* pthis,int dummy,const unsigned char *key, int keyType, int direction))0x7AE1E1;

class A{
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
		oss<<"{type:\"key\",data:{key: "<<hexBuffer(key,keylength)<<",direction:"<<direction<<"}}\n";
		std::string msg=oss.str();
		logToFile(msg.c_str());		
		char ret=oldfunc(this,0,key,keyType,direction);		
		return ret;
	}
};*/

class C00B4F258{

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

	 char func7A6807(char *dhpublicnumber, unsigned int length){
		int ret=oldfunc7A6807(this,0,dhpublicnumber,length);
		std::ostringstream oss;
		oss<<"{type: \"dhinfo\",data: {b4:"<<hexBuffer(this->b4.data,this->b4.length)<<"}}";
		std::string msg=oss.str();
		logToFile(msg.c_str());
		return ret;
	 }
};

int (__fastcall  *oldfunc7A17EA)(void* pthis,int dummy,uint8_t *dhpublicnumber, int length, int keyType)=
	(int (__fastcall  *)(void* pthis,int dummy,uint8_t *dhpublicnumber, int length, int keyType))0x007A17EA;



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
		oss<<"{type: \"secinfo\",data: {dhpublicnumber:"<<jsonArray(dhpublicnumber,length)
		<<",initiatorCert:"<<jsonArray(this->initiatorNonce->data,this->initiatorNonce->length)
		<<",responderCert:"<<jsonArray(this->responderNonce->data,this->responderNonce->length)
		<<",dhprime:"<<jsonArray(this->info->b1.data,this->info->b1.length)
		<<",dhprivatekey:"<<jsonArray(this->info->b2.data,this->info->b2.length);
		char ret=oldfunc7A17EA(this,0,dhpublicnumber,length,keyType);
		oss<<",farNonce:"<<jsonArray(this->farNonce,sizeof(this->farNonce))
			<<",nearNonce:"<<jsonArray(this->nearNonce,sizeof(this->nearNonce))
			<<"}}\n";
		std::string msg=oss.str();
		logToFile(msg.c_str());
		
		return ret;
	}
};


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


void logerror(const std::string& msg){
	std::ostringstream oss;
	oss<<"{type: \"error\",data: {error:\""<<msg<<"\"}}";
	std::string err=oss.str();
	logToFile(err.c_str());
}
class C00B0C408{
	int vtable;
	int ref;
	int socket;
public:	
	int func5DD293(uint8_t *buf, int len, int port, int addressFamily){
		std::ostringstream oss;
		oss<<"{type:\"send2\",data:";
		oss<<"{socket:"<<this->socket<<",port:"<<port<<",addressFamily:"<<addressFamily<<",data: \"";
		oss<<std::hex<<std::uppercase;
		for(int i=0;i!=len;++i)
			oss<<hexchar(buf[i]>>4)<<hexchar(buf[i]&0xF);
		oss<<"\"}}\n";
		std::string msg=oss.str();
		logToFile(msg.c_str());
		return oldfunc5DD293(this,0,buf,len,port,addressFamily);
	}

	int func5DD07D(uint8_t *buf, int len, C00AFE190* a4){
		sockaddr* addr=(sockaddr*)a4->buffer;
		if(addr->sa_family==AF_INET){
			sockaddr_in* inaddr=(sockaddr_in*)addr;
			std::ostringstream oss;
			oss<<"{type:\"send\",data:";
			oss<<"{socket:"<<this->socket<<",addr:\""<<inet_ntoa(inaddr->sin_addr)<<"\",port:"<<(unsigned short)ntohs(inaddr->sin_port)<<",data: \"";
			oss<<std::hex<<std::uppercase;
			for(int i=0;i!=len;++i)
				oss<<hexchar(buf[i]>>4)<<hexchar(buf[i]&0xF);
			oss<<"\"}}\n";
			std::string msg=oss.str();
			logToFile(msg.c_str());
		}else {
			logerror("Unknown protocol");
		}	
		return oldfunc5DD07D(this,0,buf,len,a4);
	}

	 int func5DCFFE(uint8_t *buf, int len, C00AFE190* a4){
		 int ret=oldfunc5DCFFE(this,0,buf,len,a4);		 
		 sockaddr* addr=(sockaddr*)a4->buffer;
		 if(addr->sa_family==AF_INET){
			 sockaddr_in* inaddr=(sockaddr_in*)addr;
			 std::ostringstream oss;
			 oss<<"{type:\"recv\",data:";
			 oss<<"{socket:"<<this->socket<<",addr:\""<<inet_ntoa(inaddr->sin_addr)<<"\",port:"<<(unsigned short)ntohs(inaddr->sin_port)<<",data: \"";
			 oss<<std::hex<<std::uppercase;
			 for(int i=0;i!=ret;++i)
				 oss<<hexchar(buf[i]>>4)<<hexchar(buf[i]&0xF);
			 oss<<"\"}}\n";
			 std::string msg=oss.str();
			 logToFile(msg.c_str());
		 } else {
			 logerror("Unknown protocol");
		 }				
		 return ret;
	 }
};




static void doRegister(){
	LONG error;
	DetourTransactionBegin();
	DetourUpdateThread( GetCurrentThread() );

	//DetourAttach( &(PVOID &)oldfunc,(PVOID)(&(PVOID&) A::newfunc));
	
	//DetourAttach( &(PVOID &)oldfunc7A6807,(PVOID)(&(PVOID&) C00B4C8E8::func7A6807));	
	DetourAttach( &(PVOID &)oldfunc7A17EA,(PVOID)(&(PVOID&) C00B4C820::func007A17EA));	
	DetourAttach( &(PVOID &)oldfunc5DD293,(PVOID)(&(PVOID&) C00B0C408::func5DD293));	
	DetourAttach( &(PVOID &)oldfunc5DCFFE,(PVOID)(&(PVOID&) C00B0C408::func5DCFFE));	
	DetourAttach( &(PVOID &)oldfunc5DD07D,(PVOID)(&(PVOID&) C00B0C408::func5DD07D));		
	error=DetourTransactionCommit(); 
	if(error==NO_ERROR){
		logToFile("{type:\"begin\"}\n");
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
	//DetourDetach( &(PVOID &)oldfunc,(PVOID)(&(PVOID&) A::newfunc));
	error=DetourTransactionCommit(); 
	logToFile("{type:\"end\"}\n");
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

