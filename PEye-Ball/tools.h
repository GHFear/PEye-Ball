#pragma once


void* add_base_offset(void* exe_base, int offset)
{
	return static_cast<char*>(exe_base) + offset;
}

void* add_base_offset_rva(void* exe_base, int offset, int rva)
{
	return static_cast<char*>(exe_base) + offset - rva;
}

DWORD get_disk_rva_translation(PE_DATABASE* database)
{
    try
    {
        if (database->nt_headers->FileHeader.NumberOfSections == 0) { return -1; }

        for (int i = 0; i < database->nt_headers->FileHeader.NumberOfSections; i++)
        {
            uint32_t section_start_virtual = database->section_header[i]->VirtualAddress;
            uint32_t section_end_virtual = database->section_header[i]->VirtualAddress + database->section_header[i]->Misc.VirtualSize;
            uint32_t import_directory_va = database->nt_headers->OptionalHeader.DataDirectory[1].VirtualAddress;
            uint32_t pointer_to_raw_data = database->section_header[i]->PointerToRawData;

            if (section_start_virtual < import_directory_va && section_end_virtual > import_directory_va)
            {
                return section_start_virtual - pointer_to_raw_data;
            }
        }
    }
    catch (const std::exception& error)
    {
        printf("Error: { %s }\n", error.what()); return -1;
    }
    return -1;
}