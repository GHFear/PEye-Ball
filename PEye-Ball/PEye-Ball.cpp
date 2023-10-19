#include "includes/shared_headers.h"

int main(int argc, char* argv[]) 
{

	//Intro
	const char* gh_disasm_version = "0.0.8";
	#ifdef __linux__
	if (!print_intro(gh_disasm_version)) {
		printf("Press any key to exit...\n");
		int pause = getchar();
		exit(1);
	}
	#elif _WIN64
	if (!print_intro(gh_disasm_version)) {
	system("Pause");
	exit(1);
	}
	#endif
	

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
	return 1;
}