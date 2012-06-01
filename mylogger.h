#pragma once

#include <stdlib.h>
#include <string.h>
#include <stdio.h>


typedef void (*LoggingFunction)(const char*);
 void (__cdecl *const redirectLogOutput)(LoggingFunction func)=(void (__cdecl *)(LoggingFunction func))0x008683A0;
 int (__cdecl *const VMPI_log)(const char *lpOutputString)=(int  (__cdecl *)(const char *lpOutputString))0x0083AC00;

void closeLogFile();
void initLogFile(const char* filename);




// Helper for RawLog__ below.
inline static bool VADoRawLog(char** buf, int* size,
	const char* format, va_list ap) {
		int n = vsnprintf(*buf, *size, format, ap);
		if (n < 0 || n > *size) return false;
		*size -= n;
		*buf += n;
		return true;
}

inline const char* const_basename(const char* filepath) {
	const char* base = strrchr(filepath, '/');
	if (!base)
		base = strrchr(filepath, '\\');
	return base ? (base+1) : filepath;
}


void mylog(const char* file, int line,  const char* format,...);

#define DLOG(...) mylog(__FILE__,__LINE__,__VA_ARGS__)


