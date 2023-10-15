#pragma once

bool print_dos_header(PE_DATABASE* database)
{
	try
	{
		wprintf(L"( DOS HEADER )\n");
		wprintf(L"Magic number: %04X\n", database->dos_header->e_magic);
		wprintf(L"Bytes on last page of file: %04X\n", database->dos_header->e_cblp);
		wprintf(L"Pages in file: %04X\n", database->dos_header->e_cp);
		wprintf(L"Relocations: %04X\n", database->dos_header->e_crlc);
		wprintf(L"Size of header in paragraphs: %04X\n", database->dos_header->e_cparhdr);
		wprintf(L"Minimum extra paragraphs needed: %04X\n", database->dos_header->e_minalloc);
		wprintf(L"Maximum extra paragraphs needed: %04X\n", database->dos_header->e_maxalloc);
		wprintf(L"Initial (relative) SS value: %04X\n", database->dos_header->e_ss);
		wprintf(L"Initial SP value: %04X\n", database->dos_header->e_sp);
		wprintf(L"Checksum: %04X\n", database->dos_header->e_csum);
		wprintf(L"Initial IP value: %04X\n", database->dos_header->e_ip);
		wprintf(L"Initial (relative) CS value: %04X\n", database->dos_header->e_cs);
		wprintf(L"File address of relocation table: %04X\n", database->dos_header->e_lfarlc);
		wprintf(L"Overlay number: %04X\n", database->dos_header->e_ovno);
		for (size_t i = 0; i < 4; i++)
		{
			wprintf(L"Reserved words: %04X\n", database->dos_header->e_res[i]);
		}
		wprintf(L"OEM identifier: %04X\n", database->dos_header->e_oemid);
		wprintf(L"OEM information: %04X\n", database->dos_header->e_oeminfo);
		for (size_t i = 0; i < 10; i++)
		{
			wprintf(L"Reserved words: %04X\n", database->dos_header->e_res2[i]);
		}
		wprintf(L"File address of new exe header: %ld\n\n", database->dos_header->e_lfanew);
	}
	catch (const std::exception&error)
	{
		printf("%s\n", error.what());
		return false;
	}
	
	return true;
};


bool print_nt_headers(PE_DATABASE* database)
{
	try
	{
		wprintf(L"( NT HEADERS64 )\n");
		wprintf(L"Signature: %08X\n\n", database->nt_headers->Signature);
		wprintf(L"< FILE HEADER >\n");
		wprintf(L"Machine: %04X\n", database->nt_headers->FileHeader.Machine);
		wprintf(L"NumberOfSections: %04X\n", database->nt_headers->FileHeader.NumberOfSections);
		wprintf(L"TimeDateStamp: %08X\n", database->nt_headers->FileHeader.TimeDateStamp);
		wprintf(L"PointerToSymbolTable: %08X\n", database->nt_headers->FileHeader.PointerToSymbolTable);
		wprintf(L"NumberOfSymbols: %08X\n", database->nt_headers->FileHeader.NumberOfSymbols);
		wprintf(L"SizeOfOptionalHeader: %04X\n", database->nt_headers->FileHeader.SizeOfOptionalHeader);
		wprintf(L"Characteristics: %04X\n\n", database->nt_headers->FileHeader.Characteristics);
		wprintf(L"< FILE HEADER >\n");
		wprintf(L"Magic: %04X\n", database->nt_headers->OptionalHeader.Magic);
		wprintf(L"MajorLinkerVersion: %02X\n", database->nt_headers->OptionalHeader.MajorLinkerVersion);
		wprintf(L"MinorLinkerVersion: %02X\n", database->nt_headers->OptionalHeader.MinorLinkerVersion);
		wprintf(L"SizeOfCode: %08X\n", database->nt_headers->OptionalHeader.SizeOfCode);
		wprintf(L"SizeOfInitializedData: %08X\n", database->nt_headers->OptionalHeader.SizeOfInitializedData);
		wprintf(L"SizeOfUninitializedData: %08X\n", database->nt_headers->OptionalHeader.SizeOfUninitializedData);
		wprintf(L"AddressOfEntryPoint: %08X\n", database->nt_headers->OptionalHeader.AddressOfEntryPoint);
		wprintf(L"BaseOfCode: %08X\n", database->nt_headers->OptionalHeader.BaseOfCode);
		wprintf(L"ImageBase: %llu\n", database->nt_headers->OptionalHeader.ImageBase);
		wprintf(L"SectionAlignment: %08X\n", database->nt_headers->OptionalHeader.SectionAlignment);
		wprintf(L"FileAlignment: %08X\n", database->nt_headers->OptionalHeader.FileAlignment);
		wprintf(L"MajorOperatingSystemVersion: %04X\n", database->nt_headers->OptionalHeader.MajorOperatingSystemVersion);
		wprintf(L"MinorOperatingSystemVersion: %04X\n", database->nt_headers->OptionalHeader.MinorOperatingSystemVersion);
		wprintf(L"MajorImageVersion: %04X\n", database->nt_headers->OptionalHeader.MajorImageVersion);
		wprintf(L"MinorImageVersion: %04X\n", database->nt_headers->OptionalHeader.MinorImageVersion);
		wprintf(L"MajorSubsystemVersion: %04X\n", database->nt_headers->OptionalHeader.MajorSubsystemVersion);
		wprintf(L"MinorSubsystemVersion: %04X\n", database->nt_headers->OptionalHeader.MinorSubsystemVersion);
		wprintf(L"Win32VersionValue: %08X\n", database->nt_headers->OptionalHeader.Win32VersionValue);
		wprintf(L"SizeOfImage: %08X\n", database->nt_headers->OptionalHeader.SizeOfImage);
		wprintf(L"SizeOfHeaders: %08X\n", database->nt_headers->OptionalHeader.SizeOfHeaders);
		wprintf(L"CheckSum: %08X\n", database->nt_headers->OptionalHeader.CheckSum);
		wprintf(L"Subsystem: %04X\n", database->nt_headers->OptionalHeader.Subsystem);
		wprintf(L"DllCharacteristics: %04X\n", database->nt_headers->OptionalHeader.DllCharacteristics);
		wprintf(L"SizeOfStackReserve: %llu\n", database->nt_headers->OptionalHeader.SizeOfStackReserve);
		wprintf(L"SizeOfStackCommit: %llu\n", database->nt_headers->OptionalHeader.SizeOfStackCommit);
		wprintf(L"SizeOfHeapReserve: %llu\n", database->nt_headers->OptionalHeader.SizeOfHeapReserve);
		wprintf(L"SizeOfHeapCommit: %llu\n", database->nt_headers->OptionalHeader.SizeOfHeapCommit);
		wprintf(L"LoaderFlags: %08X\n", database->nt_headers->OptionalHeader.LoaderFlags);
		wprintf(L"NumberOfRvaAndSizes: %08X\n\n", database->nt_headers->OptionalHeader.NumberOfRvaAndSizes);
		wprintf(L"< Data Directories >\n");
		for (size_t i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
		{
			wprintf(L"< Data Directory %d >\n", i);
			wprintf(L"VirtualAddress: %08X\n", database->nt_headers->OptionalHeader.DataDirectory[i].VirtualAddress);
			wprintf(L"Size: %08X\n", database->nt_headers->OptionalHeader.DataDirectory[i].Size);
		}

		printf("\n");
		
	}
	catch (const std::exception& error)
	{
		printf("%s\n", error.what());
		return false;
	}

	return true;
};


bool print_section_headers(PE_DATABASE* database)
{
	try
	{
		for (size_t i = 0; i < database->section_header.size(); i++)
		{
			wprintf(L"( SECTION HEADER %d )\n", i);
			printf("Name: %s\n", database->section_header[i]->Name);
			wprintf(L"PhysicalAddress: %08X\n", database->section_header[i]->Misc.PhysicalAddress);
			wprintf(L"VirtualSize: %08X\n", database->section_header[i]->Misc.VirtualSize);
			wprintf(L"VirtualAddress: %08X\n", database->section_header[i]->VirtualAddress);
			wprintf(L"SizeOfRawData: %08X\n", database->section_header[i]->SizeOfRawData);
			wprintf(L"PointerToRawData: %08X\n", database->section_header[i]->PointerToRawData);
			wprintf(L"PointerToRelocations: %08X\n", database->section_header[i]->PointerToRelocations);
			wprintf(L"PointerToLinenumbers: %08X\n", database->section_header[i]->PointerToLinenumbers);
			wprintf(L"NumberOfRelocations: %04X\n", database->section_header[i]->NumberOfRelocations);
			wprintf(L"NumberOfLinenumbers: %04X\n", database->section_header[i]->NumberOfLinenumbers);
			wprintf(L"Characteristics: %08X\n\n", database->section_header[i]->Characteristics);
		}
	}
	catch (const std::exception& error)
	{
		printf("%s\n", error.what());
		return false;
	}

	return true;
};


bool print_import_functions(PE_DATABASE* database, void* exe_base, int index)
{
	try
	{
		auto rva_offset = get_disk_rva_translation(database);
		auto original_firstthunk_ptr = add_base_offset_rva(exe_base, database->import_descriptor[index]->import_desc_union.OriginalFirstThunk, rva_offset);
		auto current_original_firstthunk_ptr = original_firstthunk_ptr;
		int original_firstthunk_block_counter = 0;
		while (true)
		{
			
			wprintf(L"original_firstthunk_block_counter: %d\n", original_firstthunk_block_counter);

			THUNK_DATA64* thunk_data = (THUNK_DATA64*)current_original_firstthunk_ptr;
			auto thunkdata_function_ptr = add_base_offset_rva(exe_base, thunk_data->u1.Function, rva_offset);
			auto current_thunkdata_function_ptr = thunkdata_function_ptr;

			//Ordinal or Name check must be done.
			//Then priont function names.


			original_firstthunk_block_counter += 8;
			current_original_firstthunk_ptr = add_base_offset(original_firstthunk_ptr, original_firstthunk_block_counter);
			if (*(uint64_t*)current_original_firstthunk_ptr == 0)
			{
				break;
			}
		}
	}
	catch (const std::exception& error)
	{
		printf("%s\n", error.what());
		return false;
	}

	return true;
};


bool print_import_descriptors(PE_DATABASE* database, void* exe_base)
{
	try
	{
		auto rva_offset = get_disk_rva_translation(database);
		for (int i = 0; i < database->import_descriptor.size() - 1; i++)
		{
			wprintf(L"( IMPORT DESCRIPTOR %d )\n", i);
			auto dll_name_ptr = add_base_offset_rva(exe_base, database->import_descriptor[i]->Name, rva_offset);
			
			wprintf(L"Characteristics: %08X\n", database->import_descriptor[i]->import_desc_union.Characteristics);
			wprintf(L"OriginalFirstThunk: %08X\n", database->import_descriptor[i]->import_desc_union.OriginalFirstThunk);
			wprintf(L"TimeDateStamp: %08X\n", database->import_descriptor[i]->TimeDateStamp);
			wprintf(L"ForwarderChain: %08X\n", database->import_descriptor[i]->ForwarderChain);
			printf("Name: %s\n", (const char*)dll_name_ptr);
			wprintf(L"FirstThunk: %08X\n\n", database->import_descriptor[i]->FirstThunk);
			print_import_functions(database, exe_base, i);
		}
	}
	catch (const std::exception& error)
	{
		printf("%s\n", error.what());
		return false;
	}

	return true;
};


