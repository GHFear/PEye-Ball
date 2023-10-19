#pragma once
#pragma warning(disable:4996)
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <iostream>
#include <cstdio>
#ifdef __linux__
#include <sys/mman.h>
#include <unistd.h>
#elif _WIN64
#include <Windows.h>
#endif
#include <string>
#include <iostream>
#include <vector>
#include <map>
#include "terminal_handler.h"
#include "pe_structs.h"
#include "tools.h"
#include "print_structs.h"
#include "print_tools.h"
#include "program_handlers.h"
#include "create_database.h"