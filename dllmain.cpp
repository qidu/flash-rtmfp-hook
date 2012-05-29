#include <Windows.h>
#include <detours.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <stdint.h>

#pragma comment( lib, "detours.lib" )

//only used for detours inject
__declspec(dllexport) void __cdecl dummyfunc(void){

}

typedef void (*LoggingFunction)(const char*);
void (*redirectLogOutput)(LoggingFunction func)=(void (*)(LoggingFunction func))0x008683A0;
int (__cdecl *VMPI_log)(const char *lpOutputString)=(int  (__cdecl *)(const char *lpOutputString))0x0083AC00;

static FILE* logfile;


static bool DoRawLog(char** buf, int* size, const char* format, ...) {
	va_list ap;
	va_start(ap, format);
	int n = vsnprintf(*buf, *size, format, ap);
	va_end(ap);
	if (n < 0 || n > *size) return false;
	*size -= n;
	*buf += n;
	return true;
}

// Helper for RawLog__ below.
inline static bool VADoRawLog(char** buf, int* size,
	const char* format, va_list ap) {
		int n = vsnprintf(*buf, *size, format, ap);
		if (n < 0 || n > *size) return false;
		*size -= n;
		*buf += n;
		return true;
}

const char* const_basename(const char* filepath) {
	const char* base = strrchr(filepath, '/');
	if (!base)
		base = strrchr(filepath, '\\');
	return base ? (base+1) : filepath;
}


void mylog(const char* file, int line,  const char* format,...)
{

	__time64_t long_time;
	_time64( &long_time ); 
	struct tm t;
	errno_t err = _localtime64_s( &t, &long_time );
	if (err){
		VMPI_log("cannot get current time");
		 return;
	}
	static const int kLogBufSize = 4096;
	char buffer[kLogBufSize];
	memset(buffer,0,sizeof(buffer));
	int size = sizeof(buffer);
	char* buf = buffer;
	/*DoRawLog(&buf, &size, "%02d%02d %02d:%02d:%02d %5u %s:%d]  ",		
		1 + t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec,		
		static_cast<unsigned int>(GetCurrentThreadId()),		
		const_basename(const_cast<char *>(file)), line);*/
	DoRawLog(&buf, &size, "[%02d%02d %02d:%02d:%02d %5u]  ",		
		1 + t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec,		
		static_cast<unsigned int>(GetCurrentThreadId()));
	// Record the position and size of the buffer after the prefix
	const char* msg_start = buf;
	const int msg_size = size;
	va_list ap;
	va_start(ap, format);
	bool no_chop = VADoRawLog(&buf, &size, format, ap);
	va_end(ap);
	if (no_chop) {
		DoRawLog(&buf, &size, "\n");
	} else {
		DoRawLog(&buf, &size, "LOG ERROR: The Message was too long!\n");
	}	
	VMPI_log(buffer);
}

#define DLOG(...) mylog(__FILE__,__LINE__,__VA_ARGS__)

static void logToFile(const char* s)
{
	fprintf(logfile, "%s", s);
	fflush(logfile);
}

static void initLogFile(const char* filename){
	logfile=fopen(filename,"a+");	
	if(logfile!=NULL)
		redirectLogOutput(logToFile);
}

static void closeLogFile(){
	redirectLogOutput(NULL);
	if(logfile!=NULL)
		fclose(logfile);
}



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
		oss<<"key="<<std::hex;
		for(int i=0;i!=keylength;++i){
			oss<<"0x"<<(int)key[i]<<" ";		
		}
		oss<<" direction="<<direction;
		std::string msg=oss.str();
		DLOG("%s",msg.c_str());		
		char ret=oldfunc(this,0,key,keyType,direction);		
		return ret;
	}
};

class AddressInfo{
public:
	int vtable;
	int ref;
	sockaddr_in addr;
};

static std::string printchunk(int chunkType,const unsigned char * packetData, const unsigned char * packetDataEnd){
	std::ostringstream oss;
	oss<<"\n\tchunk: type="<<std::hex<<std::uppercase<<"0x"<<chunkType<<", body= ";
	if(packetData==packetDataEnd)
		oss<<"empty";
	else{
		oss<<std::setfill('0');
		for(const unsigned char * p=packetData;p!=packetDataEnd;++p){
			oss<<std::setw(2)<<(int)*p;
		}
	}
	return oss.str();
}


int (__fastcall  *oldfunc7B2DCE)(void* pthis,int dummy,AddressInfo* addrinfo,int sessionid, int arg)=
	(int (__fastcall  *)(void* pthis,int dummy,AddressInfo* addrinfo,int sessionid, int arg))0x7B2DCE;
int (__fastcall  *oldfunc7A9357)(void* pthis,int dummy,AddressInfo* addrinfo,int sessionid, int arg)=
	(int (__fastcall  *)(void* pthis,int dummy,AddressInfo* addrinfo,int sessionid, int arg))0x7A9357;


class C00B4F30C{
	int vtable;
	int ref;
	uint8_t * pC00B4C77C;
public:
	void newfunc(AddressInfo* addrinfo,int sessionid, int arg){
		uint8_t flags=*(this->pC00B4C77C+0x344);
		uint32_t pos=*(this->pC00B4C77C+0x235C);
		uint32_t remainLength=*(this->pC00B4C77C+0x2354);
		uint8_t* rdptr=*(uint8_t**)(this->pC00B4C77C+0x2350);
		rdptr+=pos;		
		uint8_t* endptr=rdptr+remainLength;

		std::ostringstream oss;		
		oss<<"received packet from "<<inet_ntoa(addrinfo->addr.sin_addr)<<":"<<ntohs(addrinfo->addr.sin_port)<<",flags=0x"<<std::hex<<(int)flags<<std::dec<<",length="<<remainLength<<",sessionid="<<sessionid;
		if(flags & 0x8){
			uint32_t timestamp=*(uint32_t*)(this->pC00B4C77C+0x348);
			oss<<",timestamp="<<timestamp;
		}
		if(flags & 0x4){
			uint32_t timestampEcho=*(uint32_t*)(this->pC00B4C77C+0x34C);
			oss<<",timestampEcho="<<timestampEcho;
		}
				
		while(rdptr<endptr){
			int chunkType=*rdptr;			
			rdptr++;
			if(chunkType==0xFF) break;
			int chunkLength=ntohs(*(uint16_t*)rdptr);
			rdptr+=2;
			const unsigned char * old=rdptr;
			rdptr+=chunkLength;			
			oss<<printchunk(chunkType,old,rdptr);
		}
		std::string msg=oss.str();
		DLOG("%s",msg.c_str());
	}
	int func7B2DCE(AddressInfo* addrinfo,int sessionid, int arg){
		newfunc(addrinfo,sessionid,arg);
		return oldfunc7B2DCE(this,0,addrinfo,sessionid,arg);
	}

	int func7A9357(AddressInfo* addrinfo,int sessionid, int arg){
		newfunc(addrinfo,sessionid,arg);
		return oldfunc7A9357(this,0,addrinfo,sessionid,arg);
	}
};

class C00AFE190{
public:
	int vtable;
	void* unknown1;
	char buffer[0x80];
	int unknown2;
};

int (__fastcall  *oldfunc5DCFFE)(void* pthis,int dummy,char *buf, int len, C00AFE190* a4)=
	(int (__fastcall *)(void* pthis,int dummy,char *buf, int len, C00AFE190* a4))0x005DCFFE;

class C00B0C408{
public:	
	 int func5DCFFE(char *buf, int len, C00AFE190* a4){
		 int ret=oldfunc5DCFFE(this,0,buf,len,a4);
		 sockaddr* addr=(sockaddr*)a4->buffer;
		 if(addr->sa_family==AF_INET){
			 sockaddr_in* inaddr=(sockaddr_in*)addr;
			 DLOG("received udp packet from %s:%hd,len=%d",inet_ntoa(inaddr->sin_addr),ntohs(inaddr->sin_port),ret);
		 } else {
			 DLOG("received udp packet from unknown address,protocol family=%hd",addr->sa_family);
		 }				
		 return ret;
	 }
};

static int  (__cdecl *pAVMPI_reserveMemoryRegion)(LPVOID lpAddress, SIZE_T dwSize)=(int  (__cdecl *)(LPVOID lpAddress, SIZE_T dwSize))0x007BDE50;
int __cdecl myAVMPI_reserveMemoryRegion(LPVOID lpAddress, SIZE_T dwSize){
	DLOG("hooked AVMPI_reserveMemoryRegion");
	return pAVMPI_reserveMemoryRegion(lpAddress,dwSize);
}

char  (__fastcall *oldfunc7A1A22)(void* pthis,int dummy,const unsigned char * packetData, int packetDataLength, unsigned char * dest, int a5)=
	(char  (__fastcall *)(void* pthis,int dummy,const unsigned char * packetData, int packetDataLength, unsigned char * dest, int a5))0x7A1A22;

char  (__fastcall *oldfunc7A1B9E)(void* pthis,int dummy,int a2, unsigned int a3, const unsigned char * packetData, size_t* packetDataLength)=
	(char  (__fastcall *)(void* pthis,int dummy,int a2, unsigned int a3, const unsigned char * packetData, size_t* packetDataLength))0x007A1B9E;

class C00B4C820{	
public:
	

	static void printPacketInfo(std::ostream& oss,const unsigned char * packetData, int packetDataLength){
		if(packetDataLength<=0) return;
		oss<<"length="<<packetDataLength;
		const unsigned char * rdptr=packetData;
		const unsigned char * endptr=packetData+packetDataLength;
		/* dump the whole packet
		oss<<std::hex;
		for(const unsigned char * p=rdptr;p!=endptr;++p){
			oss<<"0x"<<(int)*p<<" ";
		}
		oss<<std::dec;*/

		int flags=packetData[0];
		rdptr++;
		oss<<" flags="<<std::hex<<"0x"<<flags<<std::dec;
	
		if(flags & 0x8){
			uint16_t timestamp=ntohs(*(uint16_t*)rdptr);
			rdptr+=2;
			oss<<" timestamp="<<timestamp;
		}
		if(flags & 0x4){
			uint16_t timestampEcho=ntohs(*(uint16_t*)rdptr);
			rdptr+=2;
			oss<<" timestampEcho="<<timestampEcho;
		}
		while(rdptr<endptr){
			int chunkType=*rdptr;			
			rdptr++;
			if(chunkType==0xFF) break;
			int chunkLength=ntohs(*(uint16_t*)rdptr);
			rdptr+=2;
			const unsigned char * old=rdptr;
			rdptr+=chunkLength;
			oss<<printchunk(chunkType,old,rdptr);
		}
	}
	/*
	char func7A1B9E(int a2, unsigned int a3, const unsigned char * packetData, size_t* packetDataLength){
		char ret=oldfunc7A1B9E(this,0,a2,a3,packetData,packetDataLength);
		std::ostringstream oss;
		oss<<"catch received data: ";
		printPacketInfo(oss,packetData,*packetDataLength);		
		std::string msg=oss.str();
		DLOG("%s",msg.c_str());
		return ret;
	}*/
	char func7A1A22( const unsigned char * packetData, int packetDataLength, unsigned char * dest, int a5){
		std::ostringstream oss;
		oss<<"catch construct packet data: ";
		printPacketInfo(oss,packetData,packetDataLength);		
		std::string msg=oss.str();
		DLOG("%s",msg.c_str());
		char ret=oldfunc7A1A22(this,0,packetData,packetDataLength,dest,a5);
		//char ret=0;
		return ret;
	}
};

int (__fastcall *oldsub6047A9)(void* pthis, int dummy,const unsigned char* buff, int length, sockaddr_in *a4, int a5, int a6)
	=(int (__fastcall *)(void* pthis, int dummy,const unsigned char* buff, int length, sockaddr_in *a4, int a5, int a6))0x6047A9;
class C00FB30{
public:
	int sub6047A9(const unsigned char* buff, int length, sockaddr_in *a4, int a5, int a6){
		
		std::ostringstream oss;
		oss<<"sending packet to "<<inet_ntoa(a4->sin_addr)<<":"<<ntohs(a4->sin_port)<<",type="<<a6;
		/*<<",data=\n"<<std::hex;
		for(int i=0;i!=length;++i){
			oss<<"0x"<<(int)buff[i]<<" ";
		}*/
		
		std::string msg=oss.str();
		DLOG("%s",msg.c_str());
		return oldsub6047A9(this,0,buff,length,a4,a5,a6);
	}
};


static void doRegister(){
	LONG error;
	DetourTransactionBegin();
	DetourUpdateThread( GetCurrentThread() );
	//DetourAttach( &(PVOID &)pAVMPI_reserveMemoryRegion,myAVMPI_reserveMemoryRegion);
	DetourAttach( &(PVOID &)oldfunc,(PVOID)(&(PVOID&) A::newfunc));

	DetourAttach( &(PVOID &)oldfunc7B2DCE ,(PVOID)(&(PVOID&) C00B4F30C::func7B2DCE));
	DetourAttach( &(PVOID &)oldfunc7A9357,(PVOID)(&(PVOID&) C00B4F30C::func7A9357));

	DetourAttach( &(PVOID &)oldfunc5DCFFE,(PVOID)(&(PVOID&) C00B0C408::func5DCFFE));
	DetourAttach( &(PVOID &)oldfunc7A1A22,(PVOID)(&(PVOID&) C00B4C820::func7A1A22));
	//DetourAttach( &(PVOID &)oldfunc7A1B9E,(PVOID)(&(PVOID&) C00B4C820::func7A1B9E));
	
	DetourAttach( &(PVOID &)oldsub6047A9,(PVOID)(&(PVOID&) C00FB30::sub6047A9));
	error=DetourTransactionCommit(); 
	if(error==NO_ERROR){
		DLOG("attach to target process ok!");
	}
}

static void doUnRegister(){
	LONG error;
	DetourTransactionBegin();
	DetourUpdateThread( GetCurrentThread() );
	DetourDetach( &(PVOID &)oldsub6047A9,(PVOID)(&(PVOID&) C00FB30::sub6047A9));
	//DetourDetach( &(PVOID &)oldfunc7A1B9E,(PVOID)(&(PVOID&) C00B4C820::func7A1B9E));
	DetourDetach( &(PVOID &)oldfunc7A1A22,(PVOID)(&(PVOID&) C00B4C820::func7A1A22));
	DetourDetach( &(PVOID &)oldfunc5DCFFE,(PVOID)(&(PVOID&) C00B0C408::func5DCFFE));

	DetourDetach( &(PVOID &)oldfunc7A9357,(PVOID)(&(PVOID&) C00B4F30C::func7A9357));
	DetourDetach( &(PVOID &)oldfunc7B2DCE ,(PVOID)(&(PVOID&) C00B4F30C::func7B2DCE));
	

	DetourDetach( &(PVOID &)oldfunc,(PVOID)(&(PVOID&) A::newfunc));
	//DetourDetach( &(PVOID &)pAVMPI_reserveMemoryRegion,myAVMPI_reserveMemoryRegion);
	//DetourDetach(  &(PVOID &)oldfunc,(PVOID)(&(PVOID&) A::newfunc));		
	error=DetourTransactionCommit(); 
	DLOG("detach ok!");
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

