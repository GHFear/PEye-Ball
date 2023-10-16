#pragma once

enum InputType
{
	Single_Arg,
	Double_Arg,
	Invalid_Arg
};

void clean_exit(HANDLE exe_handle)
{
	if (exe_handle != nullptr) { CloseHandle(exe_handle); }
	system("pause");
	exit(1);
}

bool IsExe(const std::wstring& fileName)
{
	if (fileName.substr(fileName.rfind(L".") + 1) == L"exe") { return true; }
	else { return false; }
}

std::wstring GetNameWithoutExtensionFromFullPath(std::wstring full_path)
{
	std::wstring filename = full_path;
	const size_t last_slash_idx = filename.rfind(L"\\/");
	if (std::wstring::npos != last_slash_idx)
	{
		filename.erase(0, last_slash_idx + 1);
	}

	const size_t period_idx = filename.rfind(L".");
	if (std::wstring::npos != period_idx)
	{
		filename.erase(period_idx);
	}

	return filename;
}

auto create_exe_buffer(void* exe_file_handle)
{
	LPVOID lpBuffer = nullptr;
	DWORD number_of_bytes_to_read = 0;
	struct result { LPVOID lpBuffer; DWORD number_of_bytes_to_read; };
	try
	{
		number_of_bytes_to_read = GetFileSize(exe_file_handle, NULL);
		lpBuffer = HeapAlloc(GetProcessHeap(), 0, number_of_bytes_to_read);
		printf("   *--Created %d number of bytes for exe data!\n", number_of_bytes_to_read);
	}
	catch (const std::exception& error)
	{
		printf("Error: { %s }", error.what());
		return result{ nullptr, 0 };
	}
	return result{ lpBuffer, number_of_bytes_to_read };
}

auto process_exe(const wchar_t* file_path)
{
	struct RESULT { HANDLE loadFile; void* exe_base; };
	HANDLE loadFile = CreateFileW(file_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (loadFile == INVALID_HANDLE_VALUE)
	{
		printf("Couldn't find file to create handle!\n"); clean_exit(loadFile);
	}

	auto exe_buffer = create_exe_buffer(loadFile);
	if (exe_buffer.lpBuffer == nullptr)
	{
		printf("Exe buffer couldn't be created!\n");
		clean_exit(loadFile);
	}

	DWORD number_of_bytes_read = { 0 };
	if (!ReadFile(loadFile, exe_buffer.lpBuffer, exe_buffer.number_of_bytes_to_read, &number_of_bytes_read, NULL))
	{
		printf("Couldn't read file into buffer!\n");
		clean_exit(loadFile);
	}	printf("   *--Loaded %d number of bytes from exe into exe_buffer.lpBuffer!\n", exe_buffer.number_of_bytes_to_read);

	return RESULT{ loadFile, exe_buffer.lpBuffer };
};

std::wstring path_to_load(int argc, wchar_t* argv)
{
	std::wstring path_input_W = L"";
	const wchar_t* file_path = nullptr;
	InputType input;

	if (argc == 1)
	{
		input = Single_Arg;
	}
	else if (argc == 2) { input = Double_Arg; }
	else { input = Invalid_Arg; }

	switch (input)
	{
	case Single_Arg:
		std::cout << "\nENTER AMD64 EXE PATH: ";
		std::getline(std::wcin, path_input_W);
		file_path = path_input_W.c_str();
		break;
	case Double_Arg:
		file_path = argv;
		path_input_W = argv;
		break;
	case Invalid_Arg:
		printf("Input path is the wrong format!\n"); clean_exit(nullptr);
		break;
	default:
		clean_exit(nullptr);
		break;
	}

	//Write to log file
	FILE* pFile = nullptr;
	std::wstring file_dump_name = GetNameWithoutExtensionFromFullPath(file_path) + L".txt";
	//_wfreopen_s(&pFile, file_dump_name.c_str(), L"w", stdout);

	if (!IsExe(path_input_W)) { printf("Input path doesn't lead to an executable!\n"); clean_exit(nullptr); }

	if (!print_exe_to_load(file_path)) { clean_exit(nullptr); }

	return path_input_W;
}