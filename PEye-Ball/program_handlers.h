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
	return fileName.size() >= 4 && fileName.compare(fileName.size() - 3, 3, L"exe") == 0;
}

std::wstring GetNameWithoutExtensionFromFullPath(std::wstring full_path)
{
	size_t last_slash_idx = full_path.find_last_of(L"\\/");
	size_t period_idx = full_path.rfind(L".");


	if (last_slash_idx != std::wstring::npos && period_idx > last_slash_idx) {
		return full_path.substr(last_slash_idx + 1, period_idx - last_slash_idx - 1);
	}

	return full_path.substr(last_slash_idx + 1);
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
		return RESULT{ loadFile, nullptr };

	auto exe_buffer = create_exe_buffer(loadFile);
	DWORD number_of_bytes_read = 0;

	if (exe_buffer.lpBuffer && ReadFile(loadFile, exe_buffer.lpBuffer, exe_buffer.number_of_bytes_to_read, &number_of_bytes_read, NULL))
		printf("   *--Loaded %d bytes from exe into exe_buffer.lpBuffer!\n", number_of_bytes_read);

	if (!exe_buffer.lpBuffer || number_of_bytes_read == 0)
		clean_exit(loadFile);

	return RESULT{ loadFile, exe_buffer.lpBuffer };
};

std::wstring path_to_load(int argc, wchar_t* argv)
{
	if (argc < 1 || argc > 2) {
		printf("Input path is in the wrong format!\n");
		clean_exit(nullptr);
	}

	std::wstring path_input_W;

	if (argc == 1) {
		std::wcout << L"\nENTER AMD64 EXE PATH: ";
		std::getline(std::wcin, path_input_W);
	}
	else {
		path_input_W = argv;
	}

	if (!IsExe(path_input_W) || !print_exe_to_load(path_input_W.c_str())) {
		clean_exit(nullptr);
	}

	return path_input_W;
}