#pragma once


bool create_dos_header(PE_DATABASE* database, void* exe_base)
{
	database->dos_header = (DOS_HEADER*)exe_base;
	if (database->dos_header != nullptr) { return true; }
	return false;
};

bool create_nt_headers(PE_DATABASE* database, void* exe_base)
{
	database->nt_headers = (NT_HEADERS64*)add_base_offset(exe_base, database->dos_header->e_lfanew);
	if (database->nt_headers != nullptr) { return true; }
	return false;
};

bool create_section_headers(PE_DATABASE* database, void* exe_base)
{
	try
	{
		int section_block_counter = 0;
		for (size_t i = 0; i < database->nt_headers->FileHeader.NumberOfSections; i++)
		{
			database->section_header.push_back((SECTION_HEADER*)add_base_offset(exe_base, database->dos_header->e_lfanew + sizeof(NT_HEADERS64) + section_block_counter));
			section_block_counter += sizeof(SECTION_HEADER);
		}
	}
	catch (const std::exception&error)
	{
		printf("%s\n", error.what());
		return false;
	}
	
	return true;
};

auto create_imported_functions(PE_DATABASE* database, void* exe_base, int loop_index)
{
	struct RESULT { bool boolean; std::vector<Thunk_Collection64> thunk_collection; };
	std::vector<Thunk_Collection64> thunk_collection_vector;
	try
	{
		uint32_t disk_rva_offset = get_disk_rva_translation(database);

		if (disk_rva_offset == -1)
		{
			printf("ERROR: { disk_rva_offset == -1 }\n");
			return RESULT{ false, thunk_collection_vector };
		}

		uint64_t rva_counter = 0;

		while (true)
		{
			THUNK_DATA64* original_first_thunk = (THUNK_DATA64*)add_base_offset_rva((exe_base), ((uint64_t)database->import_descriptor[loop_index]->import_desc_union.OriginalFirstThunk + rva_counter), disk_rva_offset);

			THUNK_DATA64* first_thunk = (THUNK_DATA64*)add_base_offset_rva((exe_base), ((uint64_t)database->import_descriptor[loop_index]->FirstThunk + rva_counter), disk_rva_offset);

			if ((uintptr_t)original_first_thunk->u1.Function == 0 || first_thunk->u1.Function == 0)
				break;

			Thunk_Collection64 thunk_collection;
			thunk_collection.thunk_data64 = *original_first_thunk;

			void* function_name_address = add_base_offset_rva((exe_base), first_thunk->u1.Function, disk_rva_offset);

			if (function_name_address != nullptr)
			{
				IMPORT_BY_NAME function_names;
				function_names.Name = "";
				function_names.Hint = 0;
				if (!(first_thunk->u1.Function & 0x8000000000000000))
				{
					function_names.Name = static_cast<const char*>(function_name_address) + 2;
					function_names.Hint = *(uint16_t*)static_cast<uint16_t*>(function_name_address);
				}
				thunk_collection.import_by_name = function_names;
				thunk_collection_vector.push_back(thunk_collection);
			}
			rva_counter += 8;
		}
	}
	catch (const std::exception& error)
	{
		printf("%s\n", error.what());
		return RESULT{ false, thunk_collection_vector };
	}

	return RESULT{ true, thunk_collection_vector };
};

bool create_import_thunk_collections(PE_DATABASE* database, void* exe_base)
{
	try
	{
		for (int i = 0; i < database->import_descriptor.size(); i++)
		{
			auto thunk_collection = create_imported_functions(database, exe_base, i);
			database->import_thunk_collection.push_back(thunk_collection.thunk_collection);
		}
	}
	catch (const std::exception& error)
	{
		printf("%s\n", error.what());
		return false;
	}

	return true;
};

bool create_import_descriptors(PE_DATABASE* database, void* exe_base)
{
	try
	{
		auto rva_offset = get_disk_rva_translation(database);
		size_t importDescriptorSize = database->nt_headers->OptionalHeader.DataDirectory[1].Size - 20; // We remove 20 because the size is one too many blocks.
		if (importDescriptorSize != 0) {
			database->import_descriptor.reserve(importDescriptorSize / 20);

			for (size_t i = 0; i * 20 < importDescriptorSize; ++i) {
				database->import_descriptor.push_back((IMPORT_DESCRIPTOR*)add_base_offset_rva(
					exe_base, database->nt_headers->OptionalHeader.DataDirectory[1].VirtualAddress + i * 20, rva_offset));
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

bool create_export_functions(PE_DATABASE* database, void* exe_base)
{
	try
	{
		auto rva_offset = get_disk_rva_translation(database);
		auto functions_address = database->export_directory->AddressOfFunctions - sizeof(uint32_t);
		auto name_ordinals_address = database->export_directory->AddressOfNameOrdinals - sizeof(uint16_t);
		auto names_address = database->export_directory->AddressOfNames - sizeof(uint32_t);

		for (size_t i = 0; i < database->export_directory->NumberOfFunctions; i++)
		{
			database->export_thunk_collection.FunctionRVA.push_back(*(uint32_t*)add_base_offset_rva(exe_base, functions_address += sizeof(uint32_t), rva_offset));
			database->export_thunk_collection.NameOrdinalRVA.push_back(*(uint16_t*)add_base_offset_rva(exe_base, name_ordinals_address += sizeof(uint16_t), rva_offset));
			database->export_thunk_collection.NameRVA.push_back(*(uint32_t*)add_base_offset_rva(exe_base, names_address += sizeof(uint32_t), rva_offset));
		}
	}
	catch (const std::exception& error)
	{
		printf("%s\n", error.what());
		return false;
	}

	return true;
};

bool create_export_directory(PE_DATABASE* database, void* exe_base)
{
	try
	{
		auto rva_offset = get_disk_rva_translation(database);
		size_t export_directories_Size = database->nt_headers->OptionalHeader.DataDirectory[0].Size;

		if (export_directories_Size != 0) {
			database->export_directory = ((EXPORT_DIRECTORY*)add_base_offset_rva(
				exe_base, database->nt_headers->OptionalHeader.DataDirectory[0].VirtualAddress, rva_offset));
		}
	}
	catch (const std::exception& error)
	{
		printf("%s\n", error.what());
		return false;
	}
	
	return true;
};

bool create_delayed_import_descriptors(PE_DATABASE* database, void* exe_base)
{
	try
	{
		auto rva_offset = get_disk_rva_translation(database);
		size_t delayed_import_descriptors_Size = database->nt_headers->OptionalHeader.DataDirectory[13].Size - 32; // We remove 32 because the size is one too many blocks.
		if (delayed_import_descriptors_Size != 0) {

			for (size_t i = 0; i * 32 < delayed_import_descriptors_Size; i++)
			{
				
				database->delayed_imports_descriptor.push_back((DELAYLOAD_DESCRIPTOR*)add_base_offset_rva(
					exe_base, database->nt_headers->OptionalHeader.DataDirectory[13].VirtualAddress + i * 32, rva_offset));
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