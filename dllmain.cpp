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
	oss<<monthStr[lt.wMonth-1]<<" "<<lt.wDay<<", "<<lt.wYear<<" "<<lt.wHour<<":"<<lt.wMinute<<":"<<lt.wSecond<<"."<<lt.wMilliseconds;
	oss<<" "<<type<<" "<<data<<"\n";
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

char  (__fastcall *oldfunc)(void* pthis,int dummy,const unsigned char *key, int keyType, int direction)=(char  (__fastcall *)(void* pthis,int dummy,const unsigned char *key, int keyType, int direction))0x7AE1E1;


/**
 * 地址信息
 */
class SockAddr{
public:
	int vtable;
	void* unknown1;	
	union {
		ADDRESS_FAMILY  sin_family;
		sockaddr_in v4;
		sockaddr_in6 v6;
	};
	int addrlen;
};

static_assert(sizeof(SockAddr)==0x28,"size error");
std::string sockAddrToString(SockAddr* a4){
	char ipstringbuffer[128];
	DWORD ipstringbufferLength=128;

	size_t addrlen;
	if(a4->sin_family==AF_INET) addrlen=sizeof(sockaddr_in);
	else if(a4->sin_family==AF_INET6) addrlen=sizeof(sockaddr_in6);
	else throw std::runtime_error("unknown addrtype");
	WSAAddressToStringA((LPSOCKADDR)&a4->v4,addrlen,NULL,ipstringbuffer,&ipstringbufferLength);
	return std::string(ipstringbuffer);
}

struct ListItem
{
	ListItem *next;
	ListItem *prev;
	void *itemptr;
	char flag;
};

struct Data
{
	int *vtable;
	int unknown;
	uint8_t *data;
	int length;
	int pos;
	char flags;
};

struct RtmfpList
{
	int vtable;
	int ref;
	int cap;
	int unknown;
	int size;
	int (__cdecl *onAdd)(int);
	int (__cdecl *onDel)(int);
	ListItem *begin;
	char buf[64];
};

struct RandomNumberGenerator
{
	int vtable;
	int ref;
	void *randomProvider;
};


struct BasicCryptoIdentity
{
	int vtable;
	int ref;
	Data *peerid;
	Data *hexPeerID;
	Data *data3;
	Data *url;
};

struct BasicCryptoCert
{
	int vtable;
	int ref;
	Data cert;
	int len;
	Data *p1;
	int v1;
	int v2;
	int v3;
	int v4;
	int v5;
	int v6;
	char flag;
	char _padding[3];
};

struct SHA256Context
{
	char data[120];
};


struct HMACSHA256Context
{
	int vtable;
	int ref;
	SHA256Context c1;
	SHA256Context c2;
	SHA256Context c3;
};


struct IndexSet
{
	int vtable;
	int ref;
	RtmfpList list;
};



class BasicCryptoKey;

struct BasicCryptoAdapter
{
	int vtable;
	Data *d1;
	Data d2;
	RandomNumberGenerator *rand;
	BasicCryptoKey *key;
	BasicCryptoIdentity id;
	BasicCryptoCert cert;
	int v1;
	bool b1;
	int v2;
	int v3;
	int v4;
	int v5;
	int v6;
};

struct Dictionary
{
	char data[48];
};

struct Set
{
	char data[48];
};

struct InstanceTimerList
{
	char data[64];
};

struct Instance;

void  (__fastcall *oldNoSessionProcessInput)(void* pthis,int dummy,SockAddr *addressInfo, int sessionid, int interfaceid)
	=(void  (__fastcall *)(void* pthis,int dummy,SockAddr *addressInfo, int sessionid, int interfaceid))0x7B2DCE;

void  (__fastcall *oldSessionProcessInput)(void* pthis,int dummy,SockAddr *addressInfo, int sessionid, int interfaceid)
	=(void  (__fastcall *)(void* pthis,int dummy,SockAddr *addressInfo, int sessionid, int interfaceid))0x7A9357;

struct NoSession
{
	int vtable;
	int ref;
	Instance *instance;
	RtmfpList nosessionItems;
	void processInput(SockAddr *addressInfo, int sessionid, int interfaceid);
	
};

char  (__fastcall *oldfillPacketHeader)(void* pthis,int dummy,int a1,int sessionid)=(char  (__fastcall *)(void* pthis,int dummy,int a1,int sessionid))0x0079F539;



struct Instance
{
	int vtable;
	int ref;
	void *rtmfpPlatformAdapter;
	void *rtmpMetadataAdapter;
	BasicCryptoAdapter *basicCryptoAdapter;
	void *p1;
	int v1;
	RtmfpList interfaces;
	RtmfpList sessions;
	Dictionary dic1;
	Dictionary dic2;
	Set s1;
	Dictionary dic3;
	Dictionary dic4;
	InstanceTimerList timers;
	RtmfpList l1;
	NoSession nosession;
	char rand1[64];
	char rand2[32];
	int v2;
	int v3;
	int v4;
	char flags;
	char gap_345[3];
	int timestamp;
	int timestampEcho;
	char recvbuf[8192];
	char *ptr;
	size_t len;
	int v5;
	int pos;
	char sendbuf[8196];
	size_t v7;
	Data d1;
	int v8;
	void *p2;
	int v9;
	int v10;
	int v11;
	int v12;
	int v13;
	int v14;
	bool b1;
	bool b2;
	char gap_43A2[2];
	int v15;
	bool v16;
	bool v17;
	char gap_43AA[2];
	int v18;
	int fillPacketHeader(int a1,int sessionid){		
		std::ostringstream oss;		
		oss<<"sessionid:"<<sessionid<<",data: "<<hexBuffer((unsigned char*)this->ptr,this->len);		
		std::string msg=oss.str();
		logToFile("createPacket",msg);
		int ret=oldfillPacketHeader(this,0,a1,sessionid);
		return ret;
	}
};


void NoSession::processInput(SockAddr *addressInfo, int sessionid, int interfaceid){
	std::ostringstream oss;		
	oss<<"sessionid:"<<sessionid<<",addr:"<<sockAddrToString(addressInfo)<<",data: "<<hexBuffer((unsigned char*)this->instance->ptr,this->instance->len);		
	std::string msg=oss.str();
	logToFile("NoSesionProcessInput",msg);
	oldNoSessionProcessInput(this,0,addressInfo,sessionid,interfaceid);
}


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
		oss<<"key: "<<hexBuffer(key,keylength)<<",direction:"<<direction;
		logToFile("keyinfo",oss.str());	
		char ret=oldfunc(this,0,key,keyType,direction);		
		return ret;
	}
};



char (__fastcall  *oldfunc7A6807)(void* pthis,int dummy,char *dhpublicnumber, unsigned int length)=
	(char (__fastcall*)(void* pthis,int dummy,char *dhpublicnumber, unsigned int length))0x007A6807;

/**
 * DiffieHellmanContext::DiffieHellmanContext vtable=00B4C8E8
 */
class DiffieHellmanContext{
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
 * RTMFP::BasicCryptoKey vtable=00B4C820
 */
class BasicCryptoKey{
public:
	int vtable;
	int ref;
	int v1;
	int v2;
	DiffieHellmanContext *info;
	int v4;
	HMACSHA256Context *hmacContext;
	int v6;
	int v7;
	HMACSHA256Context *hmacContext2;
	int v9;
	int v10;
	int writeSSEQ;
	int v12;
	__int64 seq;
	int v15;
	IndexSet *v16;
	Data *initiatorNonce;
	Data *responderNonce;
	uint8_t nearNonce[32];
	uint8_t farNonce[32];
	

	char func007A17EA(uint8_t *dhpublicnumber, int length, int keyType){
		std::ostringstream oss;
		oss<<"dhpublicnumber:"<<hexBuffer(dhpublicnumber,length)
		<<",initiatorCert:"<<hexBuffer(this->initiatorNonce->data,this->initiatorNonce->length)
		<<",responderCert:"<<hexBuffer(this->responderNonce->data,this->responderNonce->length)
		<<",dhprime:"<<hexBuffer(this->info->b1.data,this->info->b1.length)
		<<",dhprivatekey:"<<hexBuffer(this->info->b2.data,this->info->b2.length);
		char ret=oldfunc7A17EA(this,0,dhpublicnumber,length,keyType);
		oss<<",farNonce:"<<hexBuffer(this->farNonce,sizeof(this->farNonce))
			<<",nearNonce:"<<hexBuffer(this->nearNonce,sizeof(this->nearNonce));
		std::string msg=oss.str();
		logToFile("secinfo",msg.c_str());
		
		return ret;
	}
};

struct SparseArray
{
	char data[48];
};

struct SumList
{
	int vtable;
	int ref;
	int cap;
	int unknown;
	int unknown2;
	int (__cdecl *onAdd)(int);
	int (__cdecl *onDel)(int);
	ListItem *begin;
	char buf[64];
	int unknown3;
	int unknown4;
};


struct Session
{
	int vtable;
	int ref;
	Instance *instance;
	int v1;
	int v2;
	int responderSessionID;
	SockAddr addr;
	int interfaceId;
	int v4;
	int v5;
	int v6;
	int v7;
	int v8;
	int v9;
	int v10;
	int v11;
	int v12;
	int v13;
	int v14;
	int v15;
	int v16;
	int v17;
	int v18;
	int v19;
	int v20;
	int v21;
	int v22;
	int timestamp;
	int timestampEcho;
	int v23;
	int v24;
	Data *epd;
	Data *tag;
	Data *initiatorNonce;
	int v25;
	int v26;
	int v27;
	int v28;
	int v29;
	int v30;
	int v31;
	int v32;
	int v33;
	int v34;
	int v35;
	int v36;
	int v37;
	int v38;
	int v39;
	void *v40;
	int v41;
	int v42;
	int v43;
	RtmfpList list1;
	SparseArray flows;
	Set set1;
	SumList sl;
	RtmfpList lists[8];
	char f1;
	char f2;
	char f3;
	char gap_523[1];
	int vend;
	void Session::processInput(SockAddr *addressInfo, int sessionid, int interfaceid){
		std::ostringstream oss;		
		oss<<"sessionid:"<<sessionid<<",addr:"<<sockAddrToString(addressInfo)<<",data: "<<hexBuffer((unsigned char*)this->instance->ptr,this->instance->len);		
		std::string msg=oss.str();
		logToFile("SesionProcessInput",msg);
		oldSessionProcessInput(this,0,addressInfo,sessionid,interfaceid);
	}

};

int (__fastcall  *oldfunc5DCFFE)(void* pthis,int dummy,uint8_t *buf, int len, SockAddr* a4)=
	(int (__fastcall *)(void* pthis,int dummy,uint8_t *buf, int len, SockAddr* a4))0x005DCFFE;

int (__fastcall  *oldfunc5DD07D)(void* pthis,int dummy,uint8_t *buf, int len, SockAddr* a4)=
	(int (__fastcall *)(void* pthis,int dummy,uint8_t *buf, int len, SockAddr* a4))0x005DD07D;

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
 * 网络管理器。它的构造函数会调用WSAStartup
 */
class C00B0C408{
	int vtable;
	int ref;
	int socket;
public:	
	int func5DD293(uint8_t *buf, int len, int port, int addressFamily){
		std::ostringstream oss;		
		oss<<"socket:"<<this->socket<<",port:"<<port<<",addressFamily:"<<addressFamily<<",data: "<<hexBuffer(buf,len);		
		std::string msg=oss.str();
		logToFile("send2",msg);
		return oldfunc5DD293(this,0,buf,len,port,addressFamily);
	}

	int func5DD07D(uint8_t *buf, int len, SockAddr* a4){		
		std::ostringstream oss;			
		oss<<"socket:"<<this->socket<<",addr:\""<<sockAddrToString(a4)<<"\",data: "<<hexBuffer(buf,len);				
		logToFile("send",oss.str());
		return oldfunc5DD07D(this,0,buf,len,a4);
	}	
	int func5DCFFE(uint8_t *buf, int len, SockAddr* a4){
		int ret=oldfunc5DCFFE(this,0,buf,len,a4);	
		if(ret>0){			
			std::ostringstream oss;
			oss<<"socket:"<<this->socket<<",addr:\""<<sockAddrToString(a4)<<"\",data: "<<hexBuffer(buf,ret);	
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
	DetourAttach( &(PVOID &)oldfunc7A17EA,(PVOID)(&(PVOID&) BasicCryptoKey::func007A17EA));	
	//发送局域网UDP广播
	DetourAttach( &(PVOID &)oldfunc5DD293,(PVOID)(&(PVOID&) C00B0C408::func5DD293));	
	//收到UDP包
	DetourAttach( &(PVOID &)oldfunc5DCFFE,(PVOID)(&(PVOID&) C00B0C408::func5DCFFE));	
	//发送UDP包
	DetourAttach( &(PVOID &)oldfunc5DD07D,(PVOID)(&(PVOID&) C00B0C408::func5DD07D));	

	DetourAttach( &(PVOID &)oldfillPacketHeader,(PVOID)(&(PVOID&) Instance::fillPacketHeader));	
	DetourAttach( &(PVOID &)oldNoSessionProcessInput,(PVOID)(&(PVOID&) NoSession::processInput));	
	DetourAttach( &(PVOID &)oldSessionProcessInput,(PVOID)(&(PVOID&) Session::processInput));	
	
	error=DetourTransactionCommit(); 
	if(error==NO_ERROR){
		logToFile("begin","");
	}
}

static void doUnRegister(){
	LONG error;
	DetourTransactionBegin();
	DetourUpdateThread( GetCurrentThread() );
	//DetourDetach( &(PVOID &)oldfunc7A6807,(PVOID)(&(PVOID&) DiffieHellmanContext::func7A6807));
	DetourDetach( &(PVOID &)oldfunc7A17EA,(PVOID)(&(PVOID&) BasicCryptoKey::func007A17EA));	
	DetourDetach( &(PVOID &)oldfunc5DD293,(PVOID)(&(PVOID&) C00B0C408::func5DD293));	
	DetourDetach( &(PVOID &)oldfunc5DCFFE,(PVOID)(&(PVOID&) C00B0C408::func5DCFFE));	
	DetourDetach( &(PVOID &)oldfunc5DD07D,(PVOID)(&(PVOID&) C00B0C408::func5DD07D));	
	DetourDetach( &(PVOID &)oldfunc,(PVOID)(&(PVOID&) C00B4F258::newfunc));
	DetourDetach( &(PVOID &)oldfillPacketHeader,(PVOID)(&(PVOID&) Instance::fillPacketHeader));	
	DetourDetach( &(PVOID &)oldNoSessionProcessInput,(PVOID)(&(PVOID&) NoSession::processInput));
	DetourDetach( &(PVOID &)oldSessionProcessInput,(PVOID)(&(PVOID&) Session::processInput));	
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

