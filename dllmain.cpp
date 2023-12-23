// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

#include <iostream>
#include <Windows.h>
#include <winternl.h>

typedef int(WINAPI* TrueMessageBox)(HWND, LPCWSTR, LPCWSTR, UINT);

// remember memory address of the original MessageBoxW routine
TrueMessageBox trueMessageBox = MessageBoxW;

BOOL WINAPI hookedMessageBox(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
	//LPCTSTR lpTextChanged = L"This messagebox is also changed";
	LPCTSTR lpCaptionChanged = L"Hooked MessageBox";
	return trueMessageBox(hWnd, lpText, lpCaptionChanged, uType);
}

#include <fstream>
DWORD WINAPI installIATHook(PVOID base) {
//void installIATHook(){

	std::ofstream MyFile("C://Users//%USERNAME%//Desktop//logging.txt");
	
	LPVOID imageBase = GetModuleHandle(NULL);
	if (imageBase == NULL) {
		MyFile << "module handle doesnt exist" << std::endl;
		MyFile.close();
		return FALSE;
	}

	PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)imageBase;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeaders->e_lfanew);
	
	IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	if (importsDirectory.Size == 0) //if size of the table is 0 => Import Table does not exist
	{
		MyFile << "Import table doesnt exist" << std::endl;
		MyFile.close();
		return FALSE;
	}

	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(importsDirectory.VirtualAddress + (DWORD_PTR)imageBase);

	while (importDescriptor->Name != NULL) {
		LPCSTR libraryName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)imageBase;
		MyFile << libraryName << std::endl;

		HMODULE library = LoadLibraryA(libraryName);

		if (library) {
			PIMAGE_THUNK_DATA originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->OriginalFirstThunk);
			PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->FirstThunk);

			while (originalFirstThunk->u1.AddressOfData != NULL)
			{
				// To know that a function is imported by name instead of ordinal, you must check that the highest bit is NOT set in the DWORD (i.e. 0x80000000).

				if (originalFirstThunk->u1.AddressOfData & IMAGE_ORDINAL_FLAG) {
					//MyFile << "ordinal" << std::endl;
				}
				else {
					PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)imageBase + originalFirstThunk->u1.AddressOfData);
					MyFile << functionName->Name << std::endl;

					// find MessageBoxW address
					if (std::string(functionName->Name).compare("MessageBoxW") == 0) {
						SIZE_T bytesWritten = 0;
						DWORD oldProtect = 0;
						VirtualProtect((LPVOID)(&firstThunk->u1.Function), 8, PAGE_READWRITE, &oldProtect);

						// swap MessageBoxW address with address of hookedMessageBox
						firstThunk->u1.Function = (DWORD_PTR)hookedMessageBox;
						MyFile << "installed hook" << std::endl;

						// don't free library or hook will not be part of program anymore
						//FreeLibraryAndExitThread(static_cast<HMODULE>(base), 1);
					}
				}
				++originalFirstThunk;
				++firstThunk;
			}
		}

		importDescriptor++;
		
	}
	// Close the file
	MyFile.close();

	// don't free library or hook will not be part of program anymore
	//FreeLibraryAndExitThread(static_cast<HMODULE>(base), 1);
}

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		CreateThread(nullptr, NULL, installIATHook, hModule, NULL, nullptr); break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

