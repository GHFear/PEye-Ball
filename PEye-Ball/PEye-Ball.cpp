// Multithreaded PE Parser Project By GHFear.
#include "includes/shared_headers.h"

int main(int argc, char* argv[]) 
{

	//Intro
	const char* gh_disasm_version = "0.1.2";
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

	auto log_name = GetNameWithoutExtensionFromFullPath(file_path) + ".txt";

	// Redirect C output (fprintf) to a file
	cFile = fopen(log_name.c_str(), "w");

	//Start timer (Only used for measuring performance.)
	auto start = std::chrono::high_resolution_clock::now();

	//Build Database
	PE_DATABASE* database = new PE_DATABASE;

	//Parse PE
	start_pe_parser(database, loaded_exe.exe_base, loaded_exe.loadFile);

	//Stop timer (Only used for measuring performance.)
	auto stop = std::chrono::high_resolution_clock::now();
	auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
	std::cout << "Time (in microseconds) to parse PE: " << duration.count() << std::endl;

	fclose(cFile); // Close the file when done
	
	//Exit
	clean_exit(loaded_exe.loadFile);
	return 1;
}