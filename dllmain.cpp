#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include "Console.h"

Console console;

/*--------------------------------------------------
		User32.dll MessageBox hook
----------------------------------------------------*/
LPCSTR module_name = "user32.dll";
LPCSTR function_name = "MessageBoxW";

typedef int(WINAPI* TrueMessageBox)(HWND, LPCWSTR, LPCWSTR, UINT);

TrueMessageBox trueMessageBox = MessageBoxW;

BOOL WINAPI MessageBoxHook(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
	LPCTSTR lpCaptionChanged = L"Hooked MessageBox";
	return trueMessageBox(hWnd, lpText, lpCaptionChanged, uType);
}

DWORD WINAPI installIATHook(PVOID base) {
	
	LPVOID imageBase = GetModuleHandle(NULL);

	PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)imageBase;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeaders->e_lfanew);
	
	IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	if (importsDirectory.Size == 0) //if size of the table is 0 => Import Table does not exist
	{
		return FALSE;
	}

	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(importsDirectory.VirtualAddress + (DWORD_PTR)imageBase);

	while (importDescriptor->Name != NULL) {
		LPCSTR libraryName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)imageBase;

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

					// find MessageBoxW address
					if (std::string(functionName->Name).compare("MessageBoxW") == 0) {
						SIZE_T bytesWritten = 0;
						DWORD oldProtect = 0;
						VirtualProtect((LPVOID)(&firstThunk->u1.Function), 8, PAGE_READWRITE, &oldProtect);

						// swap MessageBoxW address with address of hookedMessageBox
						firstThunk->u1.Function = (DWORD_PTR)MessageBoxHook;
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

	// don't free library or hook will not be part of program anymore
	//FreeLibraryAndExitThread(static_cast<HMODULE>(base), 1);
}

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
	case DLL_PROCESS_ATTACH: {
		if (!console.open()) {
			// Indicate DLL loading failed
			return FALSE;
		}
		CreateThread(nullptr, NULL, installIATHook, hModule, NULL, nullptr);
		return TRUE;
	}
		
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

