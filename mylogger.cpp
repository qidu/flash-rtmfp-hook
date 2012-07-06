#include "mylogger.h"
#include <stdarg.h>
#include <ctime>
#include <Windows.h>
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
	DoRawLog(&buf, &size, "%ld ",		
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


