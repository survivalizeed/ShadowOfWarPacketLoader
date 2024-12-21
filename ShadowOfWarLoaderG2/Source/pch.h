#ifndef PCH_H
#define PCH_H

#include "framework.h"
#include <iostream>
#include <string>
#include <optional>
#include <vector>
#include <fstream>
#include <filesystem>
#include <conio.h>
#include <Psapi.h>
#include <thread>
#include <direct.h>
#include <set>
#include <atomic>
#include <iomanip>
#include <ctime>
#include <sstream>

namespace fs = std::filesystem;
#define oc(h,color) SetConsoleTextAttribute(h, color)
#define dbgs(x) MessageBoxA(NULL, x, "", MB_ICONINFORMATION)
#define dbg(x) MessageBoxA(NULL, std::to_string(x).c_str(), "", MB_ICONINFORMATION)

#include "MinHook.h"
#include "external/ini.h"
#include "internal/types_and_linkage.h"
#include "internal/functions.h"
#include "internal/hook_loading_routines.h"

#endif
