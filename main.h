#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <Shlwapi.h>
#include <TlHelp32.h>
#include "INIReader.h"

#pragma comment(lib, "shlwapi.lib")
using namespace std;

#define MakePtr(cast, ptr, addValue) (cast)((DWORD_PTR)(ptr) + (DWORD_PTR)(addValue))
#define MakeDelta(cast, x, y)		 (cast)((DWORD_PTR)(x) - (DWORD_PTR)(y))

bool MapRemoteModule(unsigned long, char *);

unsigned long GetProcessIdByName(char *);
HMODULE GetRemoteModuleHandle(unsigned long, char *);
FARPROC GetRemoteProcAddress(unsigned long, char *, char *);

bool FixImports(unsigned long, void *, IMAGE_NT_HEADERS *, IMAGE_IMPORT_DESCRIPTOR *);
bool FixRelocs(void *, void *, IMAGE_NT_HEADERS *, IMAGE_BASE_RELOCATION *, unsigned int);
bool MapSections(HANDLE, void *, void *, IMAGE_NT_HEADERS *);

PIMAGE_SECTION_HEADER GetEnclosingSectionHeader(DWORD, PIMAGE_NT_HEADERS);
LPVOID GetPtrFromRVA(DWORD, PIMAGE_NT_HEADERS, PBYTE);

