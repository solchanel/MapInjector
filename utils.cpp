#include "main.h"


__declspec(naked) void DllCall_stub(HMODULE hMod)
{
	__asm
	{
		push 0;
		push 1;
		push[esp + 0Ch];
		mov eax, 0xDEADBEEF;
		call eax;
		mov eax, 1;
		ret;
	}
}

__declspec(naked) void DC_stubend(void) { }
bool MapModule(const char *ModuleName);
bool FixImportsLocal(void *base, IMAGE_NT_HEADERS *ntHd, IMAGE_IMPORT_DESCRIPTOR *impDesc)
{
	char *ModuleName;

	//   Loop through all the required modules
	while ((ModuleName = (char *)GetPtrFromRVA((DWORD)(impDesc->Name), ntHd, (PBYTE)base))) {
		HMODULE localMod = LoadLibrary(ModuleName);

		HMODULE hMod = GetModuleHandle(ModuleName);
		if (!hMod)
			MapModule(ModuleName);

		IMAGE_THUNK_DATA *itd = (IMAGE_THUNK_DATA *)GetPtrFromRVA((DWORD)(impDesc->FirstThunk), ntHd, (PBYTE)base);

		while (itd->u1.AddressOfData) {
			IMAGE_IMPORT_BY_NAME *iibn;
			iibn = (IMAGE_IMPORT_BY_NAME *)GetPtrFromRVA((DWORD)(itd->u1.AddressOfData), ntHd, (PBYTE)base);

			itd->u1.Function = MakePtr(DWORD, GetProcAddress(hMod, (char *)iibn->Name), NULL);

			itd++;
		}
		impDesc++;
	}

	return true;
}


bool MapSectionsLocal(void *moduleBase, void *dllBin, IMAGE_NT_HEADERS *ntHd)
{
	IMAGE_SECTION_HEADER *header = IMAGE_FIRST_SECTION(ntHd);
	unsigned int nBytes = 0;
	unsigned int virtualSize = 0;
	unsigned int n = 0;

	//   Loop through the list of sections
	for (unsigned int i = 0; ntHd->FileHeader.NumberOfSections; i++) {
		//   Once we've reached the SizeOfImage, the rest of the sections
		//   don't need to be mapped, if there are any.
		if (nBytes >= ntHd->OptionalHeader.SizeOfImage)
			break;

		//WriteProcessMemory(hProcess, MakePtr(LPVOID, moduleBase, header->VirtualAddress), MakePtr(LPCVOID, dllBin, header->PointerToRawData), header->SizeOfRawData, (LPDWORD)&n);
		memcpy(MakePtr(LPVOID, moduleBase, header->VirtualAddress), MakePtr(LPCVOID, dllBin, header->PointerToRawData), header->SizeOfRawData);

		virtualSize = header->VirtualAddress;
		header++;
		virtualSize = header->VirtualAddress - virtualSize;
		nBytes += virtualSize;

		VirtualProtect(MakePtr(LPVOID, moduleBase, header->VirtualAddress), virtualSize, header->Characteristics & 0x00FFFFFF, NULL);
	}

	return true;
}

bool MapModule(const char *ModuleName)
{
	IMAGE_DOS_HEADER *dosHd;
	IMAGE_NT_HEADERS *ntHd;

	HANDLE hFile = CreateFile(ModuleName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
		return false;

	unsigned int fSize;

	if (GetFileAttributes(ModuleName) & FILE_ATTRIBUTE_COMPRESSED)
		fSize = GetCompressedFileSize(ModuleName, NULL);
	else
		fSize = GetFileSize(hFile, NULL);

	unsigned char *dllBin = new unsigned char[fSize];
	unsigned int nBytes;

	ReadFile(hFile, dllBin, fSize, (LPDWORD)&nBytes, FALSE);
	CloseHandle(hFile);

	dosHd = MakePtr(IMAGE_DOS_HEADER *, dllBin, 0);
	if (dosHd->e_magic != IMAGE_DOS_SIGNATURE) {
		delete dllBin;
		return false;
	}

	//   Get the real PE header from the DOS stub header
	ntHd = MakePtr(IMAGE_NT_HEADERS *, dllBin, dosHd->e_lfanew);

	//   Verify the PE header
	if (ntHd->Signature != IMAGE_NT_SIGNATURE) {
		delete dllBin;
		return false;
	}

	HANDLE hProcess = GetCurrentProcess();

	if (!hProcess)
		return false;

	void *moduleBase = VirtualAlloc(NULL, ntHd->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!moduleBase)
		return false;

	void *stubBase = VirtualAlloc(NULL, MakeDelta(SIZE_T, DC_stubend, DllCall_stub), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	//   Make sure we got the memory space we wanted
	if (!stubBase)
		return false;

	//   Fix up the import table of the new module
	IMAGE_IMPORT_DESCRIPTOR *impDesc = (IMAGE_IMPORT_DESCRIPTOR *)GetPtrFromRVA((DWORD)(ntHd->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress), ntHd, (PBYTE)dllBin);

	if (ntHd->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
		FixImportsLocal((unsigned char *)dllBin, ntHd, impDesc);

	IMAGE_BASE_RELOCATION *reloc = (IMAGE_BASE_RELOCATION *)GetPtrFromRVA((DWORD)(ntHd->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress), ntHd, (PBYTE)dllBin);

	if (ntHd->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
		FixRelocs(dllBin, moduleBase, ntHd, reloc, ntHd->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);

	//   Write the PE header into the remote process's memory space
	//WriteProcessMemory(hProcess, moduleBase, dllBin, ntHd->FileHeader.SizeOfOptionalHeader + sizeof(ntHd->FileHeader) + sizeof(ntHd->Signature), (SIZE_T *)&nBytes);
	memcpy(moduleBase, dllBin, ntHd->FileHeader.SizeOfOptionalHeader + sizeof(ntHd->FileHeader) + sizeof(ntHd->Signature));

	//   Map the sections into the remote process(they need to be aligned
	//   along their virtual addresses)
	MapSectionsLocal(moduleBase, dllBin, ntHd);

	//   Change the page protection on the DllCall_stub function from PAGE_EXECUTE_READ
	//   to PAGE_EXECUTE_READWRITE, so we can patch it.
	VirtualProtect((LPVOID)DllCall_stub, MakeDelta(SIZE_T, DC_stubend, DllCall_stub), PAGE_EXECUTE_READWRITE, (DWORD *)&nBytes);

	//   Patch the stub so it calls the correct address
	*MakePtr(unsigned long *, DllCall_stub, 9) = MakePtr(unsigned long, moduleBase, ntHd->OptionalHeader.AddressOfEntryPoint);

	//   Write the stub into the remote process
	//WriteProcessMemory(hProcess, stubBase, (LPVOID)DllCall_stub, MakeDelta(SIZE_T, DC_stubend, DllCall_stub), (SIZE_T *)&nBytes);
	memcpy(stubBase, (LPVOID)DllCall_stub, MakeDelta(SIZE_T, DC_stubend, DllCall_stub));

	//   Execute our stub in the remote process
	//HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)stubBase, moduleBase, NULL, NULL);
	HANDLE hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)stubBase, moduleBase, NULL, NULL);
	WaitForSingleObject(hThread, 10 * 1000);
	DWORD ret;
	GetExitCodeThread(hThread, &ret);
	CloseHandle(hThread);
	if (ret)
		VirtualFree(stubBase, MakeDelta(SIZE_T, DC_stubend, DllCall_stub), MEM_RELEASE);

	CloseHandle(hProcess);
	delete dllBin;
	return true;
}

bool MapRemoteModule(unsigned long pId, char *module)
{
	IMAGE_DOS_HEADER *dosHd;
	IMAGE_NT_HEADERS *ntHd;

	HANDLE hFile = CreateFile(module, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
		return false;

	unsigned int fSize;

	if (GetFileAttributes(module) & FILE_ATTRIBUTE_COMPRESSED)
		fSize = GetCompressedFileSize(module, NULL);
	else
		fSize = GetFileSize(hFile, NULL);

	unsigned char *dllBin = new unsigned char[fSize];
	unsigned int nBytes;

	ReadFile(hFile, dllBin, fSize, (LPDWORD)&nBytes, FALSE);
	CloseHandle(hFile);

	dosHd = MakePtr(IMAGE_DOS_HEADER *, dllBin, 0);
	if (dosHd->e_magic != IMAGE_DOS_SIGNATURE) {
		delete dllBin;
		return false;
	}

	//   Get the real PE header from the DOS stub header
	ntHd = MakePtr(IMAGE_NT_HEADERS *, dllBin, dosHd->e_lfanew);

	//   Verify the PE header
	if (ntHd->Signature != IMAGE_NT_SIGNATURE) {
		delete dllBin;
		return false;
	}

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pId);

	if (!hProcess)
		return false;

	void *moduleBase = VirtualAllocEx(hProcess, NULL, ntHd->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!moduleBase)
		return false;

	void *stubBase = VirtualAllocEx(hProcess, NULL, MakeDelta(SIZE_T, DC_stubend, DllCall_stub), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	//   Make sure we got the memory space we wanted
	if (!stubBase)
		return false;

	//   Fix up the import table of the new module
	IMAGE_IMPORT_DESCRIPTOR *impDesc = (IMAGE_IMPORT_DESCRIPTOR *)GetPtrFromRVA((DWORD)(ntHd->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress), ntHd, (PBYTE)dllBin);

	if (ntHd->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) 
		FixImports(pId, (unsigned char *)dllBin, ntHd, impDesc);

	IMAGE_BASE_RELOCATION *reloc = (IMAGE_BASE_RELOCATION *)GetPtrFromRVA((DWORD)(ntHd->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress), ntHd, (PBYTE)dllBin);

	if (ntHd->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
		FixRelocs(dllBin, moduleBase, ntHd, reloc, ntHd->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);

	//   Write the PE header into the remote process's memory space
	WriteProcessMemory(hProcess, moduleBase, dllBin, ntHd->FileHeader.SizeOfOptionalHeader + sizeof(ntHd->FileHeader) + sizeof(ntHd->Signature), (SIZE_T *)&nBytes);

	//   Map the sections into the remote process(they need to be aligned
	//   along their virtual addresses)
	MapSections(hProcess, moduleBase, dllBin, ntHd);

	//   Change the page protection on the DllCall_stub function from PAGE_EXECUTE_READ
	//   to PAGE_EXECUTE_READWRITE, so we can patch it.
	VirtualProtect((LPVOID)DllCall_stub, MakeDelta(SIZE_T, DC_stubend, DllCall_stub), PAGE_EXECUTE_READWRITE, (DWORD *)&nBytes);

	//   Patch the stub so it calls the correct address
	*MakePtr(unsigned long *, DllCall_stub, 9) = MakePtr(unsigned long, moduleBase, ntHd->OptionalHeader.AddressOfEntryPoint);

	//   Write the stub into the remote process
	WriteProcessMemory(hProcess, stubBase, (LPVOID)DllCall_stub, MakeDelta(SIZE_T, DC_stubend, DllCall_stub), (SIZE_T *)&nBytes);

	//   Execute our stub in the remote process
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)stubBase, moduleBase, NULL, NULL);
	WaitForSingleObject(hThread, 10 * 1000);
	DWORD ret;
	GetExitCodeThread(hThread, &ret);
	CloseHandle(hThread);
	if (ret)
		VirtualFreeEx(hProcess, stubBase, MakeDelta(SIZE_T, DC_stubend, DllCall_stub), MEM_RELEASE);

	CloseHandle(hProcess);
	delete dllBin;
	return true;
}

bool MapSections(HANDLE hProcess, void *moduleBase, void *dllBin, IMAGE_NT_HEADERS *ntHd)
{
	IMAGE_SECTION_HEADER *header = IMAGE_FIRST_SECTION(ntHd);
	unsigned int nBytes = 0;
	unsigned int virtualSize = 0;
	unsigned int n = 0;

	//   Loop through the list of sections
	for (unsigned int i = 0; ntHd->FileHeader.NumberOfSections; i++) {
		//   Once we've reached the SizeOfImage, the rest of the sections
		//   don't need to be mapped, if there are any.
		if (nBytes >= ntHd->OptionalHeader.SizeOfImage)
			break;

		WriteProcessMemory(hProcess, MakePtr(LPVOID, moduleBase, header->VirtualAddress), MakePtr(LPCVOID, dllBin, header->PointerToRawData), header->SizeOfRawData, (LPDWORD)&n);

		virtualSize = header->VirtualAddress;
		header++;
		virtualSize = header->VirtualAddress - virtualSize;
		nBytes += virtualSize;

		VirtualProtectEx(hProcess, MakePtr(LPVOID, moduleBase, header->VirtualAddress), virtualSize, header->Characteristics & 0x00FFFFFF, NULL);
	}

	return true;
}

bool FixImports(unsigned long pId, void *base, IMAGE_NT_HEADERS *ntHd, IMAGE_IMPORT_DESCRIPTOR *impDesc)
{
	char *ModuleName;

	//   Loop through all the required modules
	while ((ModuleName = (char *)GetPtrFromRVA((DWORD)(impDesc->Name), ntHd, (PBYTE)base))) {
		HMODULE localMod = LoadLibrary(ModuleName);

		if (!GetRemoteModuleHandle(pId, ModuleName))
			MapRemoteModule(pId, ModuleName);

		IMAGE_THUNK_DATA *itd = (IMAGE_THUNK_DATA *)GetPtrFromRVA((DWORD)(impDesc->FirstThunk), ntHd, (PBYTE)base);

		while (itd->u1.AddressOfData) {
			IMAGE_IMPORT_BY_NAME *iibn;
			iibn = (IMAGE_IMPORT_BY_NAME *)GetPtrFromRVA((DWORD)(itd->u1.AddressOfData), ntHd, (PBYTE)base);

			itd->u1.Function = MakePtr(DWORD, GetRemoteProcAddress(pId, ModuleName, (char *)iibn->Name), NULL);

			itd++;
		}
		impDesc++;
	}

	return true;
}

bool FixRelocs(void *base, void *rBase, IMAGE_NT_HEADERS *ntHd, IMAGE_BASE_RELOCATION *reloc, unsigned int size)
{
	unsigned long ImageBase = ntHd->OptionalHeader.ImageBase;
	unsigned int nBytes = 0;

	unsigned long delta = MakeDelta(unsigned long, rBase, ImageBase);

	while (1) {
		unsigned long *locBase = (unsigned long *)GetPtrFromRVA((DWORD)(reloc->VirtualAddress), ntHd, (PBYTE)base);
		unsigned int numRelocs = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

		if (nBytes >= size) break;

		unsigned short *locData = MakePtr(unsigned short *, reloc, sizeof(IMAGE_BASE_RELOCATION));
		for (unsigned int i = 0; i < numRelocs; i++) {
			if (((*locData >> 12) & IMAGE_REL_BASED_HIGHLOW))
				*MakePtr(unsigned long *, locBase, (*locData & 0x0FFF)) += delta;

			locData++;
		}

		nBytes += reloc->SizeOfBlock;
		reloc = (IMAGE_BASE_RELOCATION *)locData;
	}

	return true;
}


FARPROC GetRemoteProcAddress(unsigned long pId, char *module, char *func)
{
	HMODULE remoteMod = GetRemoteModuleHandle(pId, module);
	HMODULE localMod = GetModuleHandle(module);

	//   Account for potential differences in base address
	//   of modules in different processes.
	unsigned long delta = MakeDelta(unsigned long, remoteMod, localMod);
	return MakePtr(FARPROC, GetProcAddress(localMod, func), delta);
}

unsigned long GetProcessIdByName(char *process)
{
	PROCESSENTRY32 pe;
	HANDLE thSnapshot;
	BOOL retval, ProcFound = false;

	thSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (thSnapshot == INVALID_HANDLE_VALUE) {
		cerr << "Unable to create processes snapshot" << endl;
		return false;
	}

	pe.dwSize = sizeof(PROCESSENTRY32);

	retval = Process32First(thSnapshot, &pe);

	while (retval) {
		if (strstr(pe.szExeFile, process)) {
			//cout << "Found process name!" << endl;
			ProcFound = true;
			break;
		}

		retval = Process32Next(thSnapshot, &pe);
		pe.dwSize = sizeof(PROCESSENTRY32);
	}

	return pe.th32ProcessID;
}

HMODULE GetRemoteModuleHandle(unsigned long pId, char *module)
{
	MODULEENTRY32 modEntry;
	HANDLE tlh = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pId);

	modEntry.dwSize = sizeof(MODULEENTRY32);
	Module32First(tlh, &modEntry);

	do {
		if (!_stricmp(modEntry.szModule, module))
			return modEntry.hModule;

		modEntry.dwSize = sizeof(MODULEENTRY32);

	} while (Module32Next(tlh, &modEntry));

	return NULL;
}

//   Matt Pietrek's function
PIMAGE_SECTION_HEADER GetEnclosingSectionHeader(DWORD rva, PIMAGE_NT_HEADERS pNTHeader)
{
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNTHeader);
	unsigned int i;

	for (i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++, section++)
	{
		// This 3 line idiocy is because Watcom's linker actually sets the
		// Misc.VirtualSize field to 0.  (!!! - Retards....!!!)
		DWORD size = section->Misc.VirtualSize;
		if (0 == size)
			size = section->SizeOfRawData;

		// Is the RVA within this section?
		if ((rva >= section->VirtualAddress) &&
			(rva < (section->VirtualAddress + size)))
			return section;
	}

	return 0;
}

//   This function is also Pietrek's
LPVOID GetPtrFromRVA(DWORD rva, IMAGE_NT_HEADERS *pNTHeader, PBYTE imageBase)
{
	PIMAGE_SECTION_HEADER pSectionHdr;
	INT delta;

	pSectionHdr = GetEnclosingSectionHeader(rva, pNTHeader);
	if (!pSectionHdr)
		return 0;

	delta = (INT)(pSectionHdr->VirtualAddress - pSectionHdr->PointerToRawData);
	return (PVOID)(imageBase + rva - delta);
}