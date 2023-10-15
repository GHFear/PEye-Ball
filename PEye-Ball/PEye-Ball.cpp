#include "shared_headers.h"

int wmain(int argc, wchar_t* argv[]) {


	wchar_t filenamePath[255] = { 0 };
	memcpy_s(&filenamePath, 255, L"LOTF2-Win64-Shipping.exe", 255);

	HANDLE loadFile = CreateFile(filenamePath, GENERIC_ALL, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (loadFile == INVALID_HANDLE_VALUE)
	{
		printf("[!] Failed to get a handle to the file - Error Code (%d)\n", GetLastError());
		CloseHandle(loadFile);
		exit(1);
	}

	DWORD nNumberOfBytesToRead = GetFileSize(loadFile, NULL);
	LPVOID lpBuffer = HeapAlloc(GetProcessHeap(), 0, nNumberOfBytesToRead);

	void* exe_base = lpBuffer; 

	DWORD lpNumberOfBytesRead = { 0 };
	if (!ReadFile(loadFile, lpBuffer, nNumberOfBytesToRead, &lpNumberOfBytesRead, NULL))
	{
		printf("[!] Failed to read the file - Error Code (%d)\n", GetLastError());
		CloseHandle(loadFile);
		exit(1);
	}

	printf("Read file correctly!\n");

	PE_DATABASE* database = new PE_DATABASE;


	database->dos_header = (DOS_HEADER*)exe_base;
	if (!print_dos_header(database))
	{
		CloseHandle(loadFile);
		exit(1);
	}

	database->nt_headers = (NT_HEADERS64*)add_base_offset(exe_base, database->dos_header->e_lfanew);
	if (!print_nt_headers(database))
	{
		CloseHandle(loadFile);
		exit(1);
	}

	int section_block_counter = 0;
	for (size_t i = 0; i < database->nt_headers->FileHeader.NumberOfSections; i++)
	{
		database->section_header.push_back((SECTION_HEADER*)add_base_offset(exe_base, database->dos_header->e_lfanew + sizeof(NT_HEADERS64) + section_block_counter));
		section_block_counter += sizeof(SECTION_HEADER);
	}
	if (!print_section_headers(database))
	{
		CloseHandle(loadFile);
		exit(1);
	}

	int DataDirectory_block_size_counter = 0;
	int DataDirectory_block_size = 20;
	auto rva_offset = get_disk_rva_translation(database);
	for (size_t i = 0; i < (database->nt_headers->OptionalHeader.DataDirectory[1].Size / DataDirectory_block_size); i++)
	{
		database->import_descriptor.push_back((IMPORT_DESCRIPTOR*)add_base_offset_rva(exe_base, database->nt_headers->OptionalHeader.DataDirectory[1].VirtualAddress + DataDirectory_block_size_counter, rva_offset));
		DataDirectory_block_size_counter += DataDirectory_block_size;
	}
	
	if (!print_import_descriptors(database, exe_base))
	{
		CloseHandle(loadFile);
		exit(1);
	}


	CloseHandle(loadFile);
}