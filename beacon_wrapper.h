/*
 * CS2BR BOF Patcher - Compatibility Layer by NVISO
 * -------------------------
 * This headerfile implements a compatibility layer that
 * 	- maps Cobalt Strike's custom BOF API calls to Brute Ratel C4's custom BOF API
 * 	- includes Win32 API imports provided to Cobalt Strike BOFs at runtime 
 */

#ifndef __BEACON_WRAPPER__
#define __BEACON_WRAPPER__

#include <windows.h>

/* 	Import functions that are by default included in CS BOFs but not in BR
	ref https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-object-files_main.htm
	The following code
		- declares the required Win32 API symbols for importing
		- overwrites existing related macros
		- defines macros for the function names so that original CS BOF source code is compatible with the fulyl qualified import name of functions */
WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress (HMODULE hModule, LPCSTR lpProcName);
WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleA (LPCSTR lpModuleName);
WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleW (LPCWSTR lpModuleName);
WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryA (LPCSTR lpLibFileName);
WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryW (LPCWSTR lpLibFileName);
WINBASEAPI BOOL  WINAPI KERNEL32$FreeLibrary (HMODULE hLibModule);

#ifdef GetProcAddress
#undef GetProcAddress
#endif
#define GetProcAddress KERNEL32$GetProcAddress
#ifdef GetModuleHandleA
#undef GetModuleHandleA
#endif
#define GetModuleHandleA KERNEL32$GetModuleHandleA
#ifdef GetModuleHandleW
#undef GetModuleHandleW
#endif
#define GetModuleHandleW KERNEL32$GetModuleHandleW
#ifdef LoadLibraryA
#undef LoadLibraryA
#endif
#define LoadLibraryA KERNEL32$LoadLibraryA
#ifdef LoadLibraryW
#undef LoadLibraryW
#endif
#define LoadLibraryW KERNEL32$LoadLibraryW
#ifdef FreeLibrary
#undef FreeLibrary
#endif
#define FreeLibrary KERNEL32$FreeLibrary

/*	Brute Ratel BOF API
	ref https://bruteratel.com/assets/badger_exports.h */
DECLSPEC_IMPORT int BadgerDispatch(WCHAR** dispatch, const char* __format, ...);
DECLSPEC_IMPORT int BadgerDispatchW(WCHAR** dispatch, const WCHAR* __format, ...);
DECLSPEC_IMPORT size_t BadgerStrlen(CHAR* buf);
DECLSPEC_IMPORT size_t BadgerWcslen(WCHAR* buf);
DECLSPEC_IMPORT void* BadgerMemcpy(void* dest, const void* src, size_t len);
DECLSPEC_IMPORT void* BadgerMemset(void* dest, int val, size_t len);
DECLSPEC_IMPORT int BadgerStrcmp(const char* p1, const char* p2);
DECLSPEC_IMPORT int BadgerWcscmp(const wchar_t* s1, const wchar_t* s2);
DECLSPEC_IMPORT int BadgerAtoi(char* string);
DECLSPEC_IMPORT PVOID BadgerAlloc(SIZE_T length);
DECLSPEC_IMPORT VOID BadgerFree(PVOID* memptr);
DECLSPEC_IMPORT BOOL BadgerSetdebug();
DECLSPEC_IMPORT ULONG BadgerGetBufferSize(PVOID buffer);

/*	Cobalt Strike BOF API
	ref https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/beacon.h
	Removed DECLSPEC_IMPORTs since we provide our own implementations as part of our compatibility layer */

 /* data API */
typedef struct {
	char* original; /* the original buffer [so we can free it] */
	char* buffer;   /* current pointer into our buffer */
	int    length;   /* remaining length of data */
	int    size;     /* total size of this buffer */
} datap;

void    BeaconDataParse(datap* parser, char* buffer, int size);
int     BeaconDataInt(datap* parser);
short   BeaconDataShort(datap* parser);
int     BeaconDataLength(datap* parser);
char* BeaconDataExtract(datap* parser, int* size);

/* format API */
typedef struct {
	char* original; /* the original buffer [so we can free it] */
	char* buffer;   /* current pointer into our buffer */
	int    length;   /* remaining length of data */
	int    size;     /* total size of this buffer */
} formatp;

void    BeaconFormatAlloc(formatp* format, int maxsz);
void    BeaconFormatReset(formatp* format);
void    BeaconFormatFree(formatp* format);
void    BeaconFormatAppend(formatp* format, char* text, int len);
void    BeaconFormatPrintf(formatp* format, char* fmt, ...);
char* BeaconFormatToString(formatp* format, int* size);
void    BeaconFormatInt(formatp* format, int value);

/* Output Functions */
#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_ERROR       0x0d
#define CALLBACK_OUTPUT_UTF8 0x20

void   BeaconPrintf(int type, char* fmt, ...);
void   BeaconOutput(int type, char* data, int len);

/* Token Functions */
BOOL   BeaconUseToken(HANDLE token) { return FALSE; } /* TODO: Implement */
void   BeaconRevertToken() { } /* TODO: Implement */
BOOL   BeaconIsAdmin() { return FALSE; } /* TODO: Implement */

/* Spawn+Inject Functions */
void   BeaconGetSpawnTo(BOOL x86, char* buffer, int length) { } /* TODO: Implement */
void   BeaconInjectProcess(HANDLE hProc, int pid, char* payload, int p_len, int p_offset, char* arg, int a_len) { } /* TODO: Implement */
void   BeaconInjectTemporaryProcess(PROCESS_INFORMATION* pInfo, char* payload, int p_len, int p_offset, char* arg, int a_len) { } /* TODO: Implement */
void   BeaconCleanupProcess(PROCESS_INFORMATION* pInfo) { } /* TODO: Implement */

/* Utility Functions */
BOOL   toWideChar(char* src, wchar_t* dst, int max) { } /* TODO: Implement */

#ifdef _MSC_VER
#pragma data_seg(".data")
__declspec(allocate(".data")) WCHAR** _dispatch = 0;
#pragma data_seg()
#else
WCHAR** _dispatch __attribute__((section(".data"))) = 0;
#endif

/*	Custom Cobalt Strike BOF API
	implementations based on trustedsec's COFFLoader
	ref https://github.com/trustedsec/COFFLoader/blob/main/beacon_compatibility.c */

/* Custom DataParser API */
void BeaconDataParse(datap* parser, char* buffer, int size) {
	if (parser == NULL) return;
	parser->original = buffer;
	parser->buffer = buffer;
	parser->size = size;
	parser->length = parser->size;
}

int BeaconDataInt(datap* parser) {
	if (parser == NULL || parser->length < sizeof(int)) return 0;
	int val = *(int*)parser->buffer;
	parser->buffer += sizeof(int);
	parser->length -= sizeof(int);
	return val;
}

short BeaconDataShort(datap* parser) {
	if (parser == NULL || parser->length < sizeof(short)) return 0;
	short val = *(short*)parser->buffer;
	parser->buffer += sizeof(short);
	parser->length -= sizeof(short);
	return val;
}

int BeaconDataLength(datap* parser) {
	return parser->length;
}

char* BeaconDataExtract(datap* parser, int* size) {
	if (parser == NULL || parser->length < sizeof(int)) return NULL;
	char* res = NULL;
	int length = 0;

	length = BeaconDataInt(parser);

	res = parser->buffer;
	if (res == NULL) return NULL;

	parser->length -= length;
	parser->buffer += length;

	if (size != NULL && res != NULL)
		*size = length;

	return res;
}

/* Custom Format API */
void BeaconFormatAlloc(formatp* format, int maxsz) {
	if (format == NULL) return;
	format->original = (char*)BadgerAlloc(maxsz);
	format->buffer = format->original;
	format->length = 0;
	format->size = maxsz;
}

void BeaconFormatReset(formatp* format) {
	if (format == NULL) return;
	BadgerMemset(format->original, 0, format->size);
	format->buffer = format->original;
	format->length = format->size;
}

void BeaconFormatFree(formatp* format) {
	if (format == NULL) return;
	if (format->original) BadgerFree((void**)(&format->original));
	format->original = NULL;
	format->buffer = NULL;
	format->length = 0;
	format->size = 0;
}

void BeaconFormatAppend(formatp* format, char* text, int len) {
	if (format == NULL || format->size < format->length + len) return;
	BadgerMemcpy(format->buffer, text, len);
	format->buffer += len;
	format->length += len;
}

/* MSVCRT import */
// TODO: Make these optional (breaks outputs though)
#include <stdarg.h>

#ifdef _MSC_VER
#define RESTRICT __restrict
#else
#define RESTRICT __restrict__
#endif

WINBASEAPI int __cdecl MSVCRT$vsnprintf(char * RESTRICT d, size_t n, const char * RESTRICT format, va_list arg);


void BeaconFormatPrintf(formatp* format, char* fmt, ...) {
	if (format == NULL) return;

	va_list args;
	int length = 0;

	va_start(args, fmt);
	length = MSVCRT$vsnprintf(NULL, 0, fmt, args);
	va_end(args);
	if (format->length + length > format->size) return;

	va_start(args, fmt);
	(void)MSVCRT$vsnprintf(format->buffer, length, fmt, args);
	va_end(args);
	format->length += length;
	format->buffer += length;
}

char* BeaconFormatToString(formatp* format, int* size) {
	*size = format->length;
	return format->original;
}

int swap_endianess(int indata) {
	int testint = 0xaabbccdd;
	int outint = indata;
	if (((unsigned char*)&testint)[0] == 0xdd) {
		((unsigned char*)&outint)[0] = ((unsigned char*)&indata)[3];
		((unsigned char*)&outint)[1] = ((unsigned char*)&indata)[2];
		((unsigned char*)&outint)[2] = ((unsigned char*)&indata)[1];
		((unsigned char*)&outint)[3] = ((unsigned char*)&indata)[0];
	}
	return outint;
}

void BeaconFormatInt(formatp* format, int value) {
	int indata = value;
	int outdata = 0;
	if (format->length + sizeof(int) > format->size) return;
	outdata = swap_endianess(indata);
	BadgerMemcpy(format->buffer, &outdata, sizeof(int));
	format->length += sizeof(int);
	format->buffer += sizeof(int);
	return;
}

/* Custom Output API */
void BeaconPrintf(int type, char* fmt, ...) {
	//TODO: Handle encodings dependent on `type`
	va_list args;
	int length = 0;
	char* buffer = NULL;

	va_start(args, fmt);
	length = MSVCRT$vsnprintf(NULL, 0, fmt, args);
	va_end(args);

	if (length <= 0) return;
	buffer = (char*)BadgerAlloc(length + 1); //+1 for the null-termination which isn't considered by vsnprintf
	if (buffer == NULL) return;
	buffer[length] = '\0';

	va_start(args, fmt);
	(void)MSVCRT$vsnprintf(buffer, length, fmt, args);
	va_end(args);

	BadgerDispatch(_dispatch, buffer);
	BadgerFree((void**)&buffer);
	return;
}

void BeaconOutput(int type, char* data, int len) {
	char* buffer = (char*)BadgerAlloc(len + 1);
	BadgerMemcpy(buffer, data, len);
	buffer[len] = '\0'; //Ensure that the data is null-terminated
	BadgerDispatch(_dispatch, buffer);
	BadgerFree((void**)&buffer);
}

#endif // __BEACON_WRAPPER__
