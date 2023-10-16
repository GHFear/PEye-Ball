#include "shared_headers.h"

int wmain(int argc, wchar_t* argv[]) 
{
	//Intro
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, 12);
	::ShowWindow(::GetConsoleWindow(), SW_SHOW);
	const char* gh_disasm_version = "0.0.8";
	if (!print_intro(gh_disasm_version)) { clean_exit(nullptr); }
	SetConsoleTextAttribute(hConsole, 15);

	//Load exe
	auto file_path = path_to_load(argc, argv[1]);
	auto loaded_exe = process_exe(file_path.c_str());

	//Build Database
	PE_DATABASE* database = new PE_DATABASE;
	if (!create_dos_header(database, loaded_exe.exe_base)) { clean_exit(loaded_exe.loadFile); }
	if (!create_nt_headers(database, loaded_exe.exe_base)) { clean_exit(loaded_exe.loadFile); }
	if (!create_section_headers(database, loaded_exe.exe_base)) { clean_exit(loaded_exe.loadFile); }
	if (!create_import_descriptors(database, loaded_exe.exe_base)) { clean_exit(loaded_exe.loadFile); }
	if (!create_thunk_collections(database, loaded_exe.exe_base)) { clean_exit(loaded_exe.loadFile); }

	//Print Database
	if (!print_dos_header(database)) { clean_exit(loaded_exe.loadFile); }
	if (!print_nt_headers(database)) { clean_exit(loaded_exe.loadFile); }
	if (!print_section_headers(database)) { clean_exit(loaded_exe.loadFile); }
	if (!print_import_descriptors(database, loaded_exe.exe_base)) { clean_exit(loaded_exe.loadFile); }

	//Exit
	clean_exit(loaded_exe.loadFile);
}