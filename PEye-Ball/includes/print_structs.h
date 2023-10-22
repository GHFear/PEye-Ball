#pragma once

bool print_dos_header(PE_DATABASE* database)
{
	try
	{
		printf("--( DOS HEADER )--\n");
		printf("  *--Magic number: %04X\n", database->dos_header->e_magic);
		printf("  *--Bytes on last page of file: %04X\n", database->dos_header->e_cblp);
		printf("  *--Pages in file: %04X\n", database->dos_header->e_cp);
		printf("  *--Relocations: %04X\n", database->dos_header->e_crlc);
		printf("  *--Size of header in paragraphs: %04X\n", database->dos_header->e_cparhdr);
		printf("  *--Minimum extra paragraphs needed: %04X\n", database->dos_header->e_minalloc);
		printf("  *--Maximum extra paragraphs needed: %04X\n", database->dos_header->e_maxalloc);
		printf("  *--Initial (relative) SS value: %04X\n", database->dos_header->e_ss);
		printf("  *--Initial SP value: %04X\n", database->dos_header->e_sp);
		printf("  *--Checksum: %04X\n", database->dos_header->e_csum);
		printf("  *--Initial IP value: %04X\n", database->dos_header->e_ip);
		printf("  *--Initial (relative) CS value: %04X\n", database->dos_header->e_cs);
		printf("  *--File address of relocation table: %04X\n", database->dos_header->e_lfarlc);
		printf("  *--Overlay number: %04X\n", database->dos_header->e_ovno);
		for (int i = 0; i < 4; i++)
		{
			printf("  *--Reserved words: %04X\n", database->dos_header->e_res[i]);
		}
		printf("  *--OEM identifier: %04X\n", database->dos_header->e_oemid);
		printf("  *--OEM information: %04X\n", database->dos_header->e_oeminfo);
		for (int i = 0; i < 10; i++)
		{
			printf("  *--Reserved words: %04X\n", database->dos_header->e_res2[i]);
		}
		printf("  *--File address of new exe header: %d\n\n", database->dos_header->e_lfanew);
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
		printf("--( NT HEADERS64 )--\n");
		printf("  *--Signature: %08X\n\n", database->nt_headers->Signature);
		printf("--< FILE HEADER >--\n");
		printf("  *--Machine: %04X\n", database->nt_headers->FileHeader.Machine);
		printf("  *--NumberOfSections: %04X\n", database->nt_headers->FileHeader.NumberOfSections);
		printf("  *--TimeDateStamp: %08X\n", database->nt_headers->FileHeader.TimeDateStamp);
		printf("  *--PointerToSymbolTable: %08X\n", database->nt_headers->FileHeader.PointerToSymbolTable);
		printf("  *--NumberOfSymbols: %08X\n", database->nt_headers->FileHeader.NumberOfSymbols);
		printf("  *--SizeOfOptionalHeader: %04X\n", database->nt_headers->FileHeader.SizeOfOptionalHeader);
		printf("  *--Characteristics: %04X\n\n", database->nt_headers->FileHeader.Characteristics);
		printf("--< FILE HEADER >--\n");
		printf("  *--Magic: %04X\n", database->nt_headers->OptionalHeader.Magic);
		printf("  *--MajorLinkerVersion: %02X\n", database->nt_headers->OptionalHeader.MajorLinkerVersion);
		printf("  *--MinorLinkerVersion: %02X\n", database->nt_headers->OptionalHeader.MinorLinkerVersion);
		printf("  *--SizeOfCode: %08X\n", database->nt_headers->OptionalHeader.SizeOfCode);
		printf("  *--SizeOfInitializedData: %08X\n", database->nt_headers->OptionalHeader.SizeOfInitializedData);
		printf("  *--SizeOfUninitializedData: %08X\n", database->nt_headers->OptionalHeader.SizeOfUninitializedData);
		printf("  *--AddressOfEntryPoint: %08X\n", database->nt_headers->OptionalHeader.AddressOfEntryPoint);
		printf("  *--BaseOfCode: %08X\n", database->nt_headers->OptionalHeader.BaseOfCode);
		printf("  *--ImageBase: %llu\n", database->nt_headers->OptionalHeader.ImageBase);
		printf("  *--SectionAlignment: %08X\n", database->nt_headers->OptionalHeader.SectionAlignment);
		printf("  *--FileAlignment: %08X\n", database->nt_headers->OptionalHeader.FileAlignment);
		printf("  *--MajorOperatingSystemVersion: %04X\n", database->nt_headers->OptionalHeader.MajorOperatingSystemVersion);
		printf("  *--MinorOperatingSystemVersion: %04X\n", database->nt_headers->OptionalHeader.MinorOperatingSystemVersion);
		printf("  *--MajorImageVersion: %04X\n", database->nt_headers->OptionalHeader.MajorImageVersion);
		printf("  *--MinorImageVersion: %04X\n", database->nt_headers->OptionalHeader.MinorImageVersion);
		printf("  *--MajorSubsystemVersion: %04X\n", database->nt_headers->OptionalHeader.MajorSubsystemVersion);
		printf("  *--MinorSubsystemVersion: %04X\n", database->nt_headers->OptionalHeader.MinorSubsystemVersion);
		printf("  *--Win32VersionValue: %08X\n", database->nt_headers->OptionalHeader.Win32VersionValue);
		printf("  *--SizeOfImage: %08X\n", database->nt_headers->OptionalHeader.SizeOfImage);
		printf("  *--SizeOfHeaders: %08X\n", database->nt_headers->OptionalHeader.SizeOfHeaders);
		printf("  *--CheckSum: %08X\n", database->nt_headers->OptionalHeader.CheckSum);
		printf("  *--Subsystem: %04X\n", database->nt_headers->OptionalHeader.Subsystem);
		printf("  *--DllCharacteristics: %04X\n", database->nt_headers->OptionalHeader.DllCharacteristics);
		printf("  *--SizeOfStackReserve: %llu\n", database->nt_headers->OptionalHeader.SizeOfStackReserve);
		printf("  *--SizeOfStackCommit: %llu\n", database->nt_headers->OptionalHeader.SizeOfStackCommit);
		printf("  *--SizeOfHeapReserve: %llu\n", database->nt_headers->OptionalHeader.SizeOfHeapReserve);
		printf("  *--SizeOfHeapCommit: %llu\n", database->nt_headers->OptionalHeader.SizeOfHeapCommit);
		printf("  *--LoaderFlags: %08X\n", database->nt_headers->OptionalHeader.LoaderFlags);
		printf("  *--NumberOfRvaAndSizes: %08X\n\n", database->nt_headers->OptionalHeader.NumberOfRvaAndSizes);
		printf("--< Data Directories >--\n");
		for (int i = 0; i < 16; i++)
		{
			printf("  *--Data Directory %d\n", i);
			printf("     *--VirtualAddress: %08X\n", database->nt_headers->OptionalHeader.DataDirectory[i].VirtualAddress);
			printf("     *--Size: %08X\n\n", database->nt_headers->OptionalHeader.DataDirectory[i].Size);
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
		for (int i = 0; i < database->section_header.size(); i++)
		{
			printf("--( SECTION HEADER %d )--\n", i);
			printf("  *--Name: %s\n", database->section_header[i]->Name);
			printf("  *--PhysicalAddress: %08X\n", database->section_header[i]->Misc.PhysicalAddress);
			printf("  *--VirtualSize: %08X\n", database->section_header[i]->Misc.VirtualSize);
			printf("  *--VirtualAddress: %08X\n", database->section_header[i]->VirtualAddress);
			printf("  *--SizeOfRawData: %08X\n", database->section_header[i]->SizeOfRawData);
			printf("  *--PointerToRawData: %08X\n", database->section_header[i]->PointerToRawData);
			printf("  *--PointerToRelocations: %08X\n", database->section_header[i]->PointerToRelocations);
			printf("  *--PointerToLinenumbers: %08X\n", database->section_header[i]->PointerToLinenumbers);
			printf("  *--NumberOfRelocations: %04X\n", database->section_header[i]->NumberOfRelocations);
			printf("  *--NumberOfLinenumbers: %04X\n", database->section_header[i]->NumberOfLinenumbers);
			printf("  *--Characteristics: %08X\n\n", database->section_header[i]->Characteristics);
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

		for (int i = 0; i < database->import_descriptor.size(); i++)
		{
			auto& importDesc = *database->import_descriptor[i];
			auto& thunkCollection = database->import_thunk_collection[i];
			auto dll_name_ptr = add_base_offset_rva(exe_base, importDesc.Name, rva_offset);

			printf("--( IMPORT DESCRIPTOR %d )--\n", i);
			printf("  *--Characteristics: %08X\n", importDesc.import_desc_union.Characteristics);
			printf("  *--OriginalFirstThunk: %08X\n", importDesc.import_desc_union.OriginalFirstThunk);
			printf("  *--TimeDateStamp: %08X\n", importDesc.TimeDateStamp);
			printf("  *--ForwarderChain: %08X\n", importDesc.ForwarderChain);
			printf("  *--Name: %s\n", (const char*)dll_name_ptr);
			printf("  *--FirstThunk: %08X\n", importDesc.FirstThunk);
			printf("  *--Functions:\n");

			for (int j = 0; j < thunkCollection.size(); j++)
			{

				printf("     *--Function: %d\n", j);

				auto& thunkData = thunkCollection[j].thunk_data64;
				auto& importByName = thunkCollection[j].import_by_name;

				if ((thunkData.u1.Function & 0x8000000000000000) == 0x8000000000000000) //Is Ordinal
				{
					auto thunk_ordinal = thunkData.u1.Ordinal & 0xFFFF;
					printf("     *--Ordinal: %llu\n\n", thunk_ordinal);
				}
				else //Is Name
				{
					printf("     *--Name: %s\n", importByName.Name);
					printf("     *--Hint: %04X\n\n", importByName.Hint);
				}
			}
		}
	}
	catch (const std::exception& error)
	{
		printf("%s\n", error.what());
		return false;
	}
	
	return true;
}

bool print_export_directory(PE_DATABASE* database, void* exe_base)
{
	try
	{
		auto rva_offset = get_disk_rva_translation(database);
		auto& export_directory = *database->export_directory;
		auto export_name_ptr = add_base_offset_rva(exe_base, export_directory.Name, rva_offset);

		printf("--( EXPORT DIRECTORY )--\n");
		printf("  *--Characteristics: %08X\n", export_directory.Characteristics);
		printf("  *--TimeDateStamp: %08X\n", export_directory.TimeDateStamp);
		printf("  *--MajorVersion: %04X\n", export_directory.MajorVersion);
		printf("  *--MinorVersion: %04X\n", export_directory.MinorVersion);
		printf("  *--Name: %s\n", (const char*)export_name_ptr);
		printf("  *--Base: %08X\n", export_directory.Base);
		printf("  *--NumberOfFunctions: %u\n", export_directory.NumberOfFunctions);
		printf("  *--NumberOfNames: %u\n", export_directory.NumberOfNames);
		printf("  *--AddressOfFunctions: %08X\n", export_directory.AddressOfFunctions);
		printf("  *--AddressOfNames: %08X\n", export_directory.AddressOfNames);
		printf("  *--AddressOfNameOrdinals: %08X\n\n", export_directory.AddressOfNameOrdinals);

	}
	catch (const std::exception& error)
	{
		printf("%s\n", error.what());
		return false;
	}

	return true;
}

bool print_export_functions(PE_DATABASE* database, void* exe_base)
{
	try
	{
		auto rva_offset = get_disk_rva_translation(database);
		auto export_function_collection = database->export_thunk_collection;

		printf("--( EXPORT FUNCTION COLLECTION )--\n");
		for (size_t i = 0; i < database->export_directory->NumberOfFunctions; i++)
		{
			auto exported_function_name_ptr = add_base_offset_rva(exe_base, export_function_collection.NameRVA[i], rva_offset);
			printf("  *--%s\n", (const char*)exported_function_name_ptr);
			printf("  *--Function RVA: %08X\n", export_function_collection.FunctionRVA[i]);
			printf("  *--Ordinal: %hu\n", export_function_collection.NameOrdinalRVA[i]);
			printf("  *--Name RVA: %08X\n\n", export_function_collection.NameRVA[i]);
		}
	}
	catch (const std::exception& error)
	{
		printf("%s\n", error.what());
		return false;
	}

	return true;
}

bool print_delayed_import_descriptors(PE_DATABASE* database, void* exe_base)
{
	try
	{
		auto rva_offset = get_disk_rva_translation(database);
		auto delayed_import_descriptors = database->delayed_imports_descriptor;

		printf("--( DELAYED IMPORT DESCRIPTORS )--\n");
		for (size_t i = 0; i < database->delayed_imports_descriptor.size(); i++)
		{
			auto delayed_import_dll_name_ptr = add_base_offset_rva(exe_base, delayed_import_descriptors[i]->DllNameRVA, rva_offset);
			printf("  *--%s\n", (const char*)delayed_import_dll_name_ptr);
			printf("  *--Attributes: %u\n", delayed_import_descriptors[i]->Attributes.AllAttributes);
			printf("  *--BoundImportAddressTableRVA: %08X\n", delayed_import_descriptors[i]->BoundImportAddressTableRVA);
			printf("  *--DllNameRVA: %08X\n", delayed_import_descriptors[i]->DllNameRVA);
			printf("  *--ImportAddressTableRVA: %08X\n", delayed_import_descriptors[i]->ImportAddressTableRVA);
			printf("  *--ImportNameTableRVA: %08X\n", delayed_import_descriptors[i]->ImportNameTableRVA);
			printf("  *--ModuleHandleRVA: %08X\n", delayed_import_descriptors[i]->ModuleHandleRVA);
			printf("  *--TimeDateStamp: %08X\n", delayed_import_descriptors[i]->TimeDateStamp);
			printf("  *--UnloadInformationTableRVA: %08X\n\n", delayed_import_descriptors[i]->UnloadInformationTableRVA);
		}
	}
	catch (const std::exception& error)
	{
		printf("%s\n", error.what());
		return false;
	}

	return true;
}