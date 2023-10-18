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
	int section_block_counter = 0;
	for (size_t i = 0; i < database->nt_headers->FileHeader.NumberOfSections; i++)
	{
		database->section_header.push_back((SECTION_HEADER*)add_base_offset(exe_base, database->dos_header->e_lfanew + sizeof(NT_HEADERS64) + section_block_counter));
		section_block_counter += sizeof(SECTION_HEADER);
	}
	if (!database->section_header.empty()) { return true; }
	return false;
};

auto create_imported_functions(PE_DATABASE* database, void* exe_base, int loop_index)
{
	std::vector<Thunk_Collection64> thunk_collection_vector;
	DWORD disk_rva_offset = get_disk_rva_translation(database);
	struct RESULT { bool boolean; std::vector<Thunk_Collection64> thunk_collection; };

	if (disk_rva_offset == -1)
	{
		printf("ERROR: { disk_rva_offset == -1 }\n");
		return RESULT{ false, thunk_collection_vector };
	}

	int rva_counter = 0;

	while (true)
	{
		THUNK_DATA64* original_first_thunk = (THUNK_DATA64*)add_base_offset_rva(exe_base, (uintptr_t)(THUNK_DATA64*)database->import_descriptor[loop_index]->import_desc_union.OriginalFirstThunk + rva_counter, disk_rva_offset);

		THUNK_DATA64* first_thunk = (THUNK_DATA64*)add_base_offset_rva(exe_base, (uintptr_t)(THUNK_DATA64*)database->import_descriptor[loop_index]->FirstThunk + rva_counter, disk_rva_offset);

		if ((uintptr_t)original_first_thunk->u1.Function == 0 || (uintptr_t)first_thunk->u1.Function == 0)
			break;

		Thunk_Collection64 thunk_collection;
		thunk_collection.thunk_data64 = *original_first_thunk;

		void* function_name_address = add_base_offset_rva(exe_base, (uintptr_t)first_thunk->u1.Function, disk_rva_offset);

		if (function_name_address != nullptr)
		{
			IMPORT_BY_NAME* function_names = new IMPORT_BY_NAME;
			if (!(first_thunk->u1.Function & 0x8000000000000000))
			{
				function_names->Name = static_cast<const char*>(function_name_address) + 2;
				function_names->Hint = *(WORD*)static_cast<WORD*>(function_name_address);
			}
			thunk_collection.import_by_name = *function_names;
			thunk_collection_vector.push_back(thunk_collection);
		}

		rva_counter += 8;
	}

	return RESULT{ true, thunk_collection_vector };
};

bool create_thunk_collections(PE_DATABASE* database, void* exe_base)
{
	try
	{
		for (int i = 0; i < database->import_descriptor.size(); i++)
		{
			auto thunk_collection = create_imported_functions(database, exe_base, i);
			database->thunk_collection.push_back(thunk_collection.thunk_collection);
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
	auto rva_offset = get_disk_rva_translation(database);
	size_t importDescriptorSize = database->nt_headers->OptionalHeader.DataDirectory[1].Size;

	if (importDescriptorSize % 20 == 0) {
		database->import_descriptor.reserve(importDescriptorSize / 20);

		for (size_t i = 0; i * 20 < importDescriptorSize -20; ++i) {
			database->import_descriptor.push_back((IMPORT_DESCRIPTOR*)add_base_offset_rva(
				exe_base, database->nt_headers->OptionalHeader.DataDirectory[1].VirtualAddress + i * 20, rva_offset));
		}

		return !database->import_descriptor.empty();
	}

	return false;
};