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

// Parse the PE header to find the address of the Import Directory Table
PIMAGE_IMPORT_DESCRIPTOR get_import_directory(UINT_PTR base)
{
	PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
	PIMAGE_NT_HEADERS ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dosHeader->e_lfanew);
	IMAGE_DATA_DIRECTORY import_data_dir = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	PIMAGE_IMPORT_DESCRIPTOR import_directory = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(base + import_data_dir.VirtualAddress);

	return import_directory;
}

// The import directory table contains one entry for each DLL and ends with a NULL entry
// Iterate the entries until and compare the names until we find the correct one
PIMAGE_IMPORT_DESCRIPTOR search_import_directory(UINT_PTR base, PIMAGE_IMPORT_DESCRIPTOR import_descriptor, LPCSTR module_name)
{
	// Search the import descriptors for the correct module
	while (import_descriptor->Characteristics != NULL) {
		// Name is a RVA to an ASCII string
		LPCSTR current_name = reinterpret_cast<LPCSTR>(base + import_descriptor->Name);

		if (_stricmp(module_name, current_name) == 0) {
			fprintf(console.stream, "Found %s in Import Directory Table\n", module_name);
			return import_descriptor;
		}

		import_descriptor++;

	}
	fprintf(console.stream, "Unable to find %s in Import Directory Table\n", module_name);
	return NULL;
}



// The ILT and IAT tables contains one entry for each function imported from the module and ends with a NULL entry
// We iterate the entries in the ILT and check the names in the Hint/Name table until we find the correct one
// Then we return the correcesponding entry from the IAT
PIMAGE_THUNK_DATA search_IAT(UINT_PTR base, PIMAGE_THUNK_DATA first_thunk, PIMAGE_THUNK_DATA original_first_thunk, LPCSTR function_name)
{
	PIMAGE_THUNK_DATA thunk = first_thunk;
	PIMAGE_THUNK_DATA original_thunk = original_first_thunk;

	while (original_thunk->u1.AddressOfData != NULL)
	{
		// To know that a function is imported by name instead of ordinal, you must check that the highest bit is NOT set in the DWORD (i.e. 0x80000000).
		if (original_thunk->u1.AddressOfData & IMAGE_ORDINAL_FLAG) {
			// Import by ordinal
		}
		else {
			// Check the Hint/Name table for the name of the function
			PIMAGE_IMPORT_BY_NAME hint_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(base + original_thunk->u1.AddressOfData);
			fprintf(console.stream, "Current function name: %s \n", hint_name->Name);

			if (std::string(hint_name->Name).compare(function_name) == 0) {
				fprintf(console.stream, "Found %s in Import Address Table\n", function_name);
				return thunk;
			}
		}
		thunk++;
		original_thunk++;
	}
	fprintf(console.stream, "Unable to find %s in Import Address Table\n", function_name);
	return NULL;
}

// Install the hook (overwrite the pointer in the Import Address Table)
void overwriteIAT(PIMAGE_THUNK_DATA thunk, UINT_PTR address) {
	// Change the protection so we can overwrite the pointer, store the old protection
	// Import table contains DWORD in 32-bit and ULONGLONG in 64-bit!
	DWORD old_protection{};
	VirtualProtect(&thunk->u1.Function, sizeof(UINT_PTR), PAGE_READWRITE, &old_protection);

	// Overwrite the address with a pointer to another function
	thunk->u1.Function = address;

	// Restore the old protection
	VirtualProtect(&thunk->u1.Function, sizeof(UINT_PTR), old_protection, &old_protection);
}

// Storing these values to be able to use them in the attach and detach
HMODULE h_module = NULL;
UINT_PTR base = 0; // Using UINT_PTR because it scales to the size of a pointer for both 32-bit and 64-bit Windows 
PIMAGE_THUNK_DATA thunk = 0; // Store this to use it for attach and detach

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH: {
		if (!console.open()) {
			// Indicate DLL loading failed
			return FALSE;
		}

		// module handle == base address of the module
		h_module = GetModuleHandle(NULL);

		// module handle == base address of the module
		// but we need to cast it to do correct pointer arithmetic
		base = (UINT_PTR)h_module;
		fprintf(console.stream, "Base address of process: %p\n", base);

		// Search the import descriptors for the correct module
		PIMAGE_IMPORT_DESCRIPTOR first_import_descriptor = get_import_directory(base);
		PIMAGE_IMPORT_DESCRIPTOR import_descriptor = search_import_directory(base, first_import_descriptor, module_name);
		if (import_descriptor == NULL) {
			return FALSE;
		}

		// The IMAGE_IMPORT_DESCRIPTOR contains pointers to 2 other tables:
		// - Import Lookup Table (ILT) = OriginalFirstThunk
		// - Import Address Table (IAT) = FirstThunk
		// these tables contain relative virtual addresses to the imported functions and end with a NULL entry
		// both tables are identical until the module is bound, then the RVAs in the IAT get overwritten with the actual addresses of the functions
		PIMAGE_THUNK_DATA first_thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(base + import_descriptor->FirstThunk);
		PIMAGE_THUNK_DATA original_first_thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(base + import_descriptor->OriginalFirstThunk);
		thunk = search_IAT(base, first_thunk, original_first_thunk, function_name);
		if (thunk == NULL) {
			return FALSE;
		}

		fprintf(console.stream, "True address:  %p\n", trueMessageBox);
		fprintf(console.stream, "Hook address:  %p\n", (UINT_PTR)&MessageBoxHook);
		fprintf(console.stream, "Thunk address: %p\n", thunk->u1.Function);

		// Overwrite the address in the IAT
		overwriteIAT(thunk, (UINT_PTR)&MessageBoxHook);
		fprintf(console.stream, "Installed hook\n");
		fprintf(console.stream, "Thunk address: %p\n", thunk->u1.Function);

		return TRUE;
	}

	case DLL_THREAD_ATTACH: break;
	case DLL_THREAD_DETACH: break;
	case DLL_PROCESS_DETACH: {
		if (thunk != NULL) {
			fprintf(console.stream, "Uninstalling hook ...\n");
			overwriteIAT(thunk, (UINT_PTR)trueMessageBox);
			fprintf(console.stream, "Thunk address: %p\n", thunk->u1.Function);
		}
		// Create a MessageBox so console doesn't close yet
		MessageBoxW(NULL, L"Press Ok to close", L"Closing", NULL);
		return TRUE;
	}
	}
	return TRUE;
}

