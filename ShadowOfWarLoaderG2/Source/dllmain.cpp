#include "pch.h"


DWORD WINAPI MainThread(LPVOID param) {
	using namespace INTERNAL::TYPES;
	using namespace INTERNAL;
	AllocConsole();
	(void)freopen("CONOUT$", "w", stdout);

	GLOBALS::console = GetConsoleWindow();
	RECT rect = { 100, 100, 1250, 1000 };
	MoveWindow(GLOBALS::console, rect.left, rect.top, rect.right - rect.left, rect.bottom - rect.top, TRUE);
	GLOBALS::ch = GetStdHandle(STD_OUTPUT_HANDLE);
	
	std::thread asyncTitle(FUNCTIONS::refreshTitle);
	asyncTitle.detach();

	MH_Initialize();

	FUNCTIONS::log(DESIGN::name + "\n", TYPES::NONE, 0, 11);

	mINI::INIFile file(".\\plugins\\PacketLoader\\Internal\\PacketLoader.ini");
	mINI::INIStructure ini;
	if (!file.read(ini)) {
		FUNCTIONS::log("Unable to find .\\plugins\\PacketLoader\\Internal\\PacketLoader.ini\n", TYPES::ERROR, 2);
		FUNCTIONS::terminate(TYPES::ERROR);
	}

	//Lazy approach
	try {
		GLOBALS::cache = (Cache)std::stoi(ini["config"]["cache"]);
		GLOBALS::debug = (bool)std::stoi(ini["config"]["debug"]);
		GLOBALS::dump_all = (bool)std::stoi(ini["config"]["dump_all"]);
		GLOBALS::re_construct = (bool)std::stoi(ini["config"]["re_construct"]);
		GLOBALS::log = (bool)std::stoi(ini["config"]["log"]);
	}
	catch (...) {
		FUNCTIONS::log("Invalid PacketLoader.ini\n", TYPES::ERROR, 2);
		FUNCTIONS::terminate(TYPES::ERROR);
	}

	if (GLOBALS::log) {
		std::time_t now = std::time(nullptr);
		std::tm localTime = *std::localtime(&now);
		std::ostringstream oss;
		oss << std::put_time(&localTime, "%d-%m-%y %H-%M-%S");

		(void)_mkdir(".\\plugins\\PacketLoader\\Internal\\Logs");
		GLOBALS::log_file_name = ".\\plugins\\PacketLoader\\Internal\\Logs\\" + oss.str() + " PacketLoader.log";
	}

	//PLG1
	{
		using namespace INTERNAL::TYPES::GLOBALS::PLG1;
		FUNCTIONS::log(DESIGN::plg1 + "\n\n", TYPES::NONE, 0, 14);
		(void)_mkdir(".\\plugins\\PacketLoader\\PLG1Packets");
		FUNCTIONS::get_loader_entries_G1();
		thwcc = std::thread::hardware_concurrency() == 0 ? 1 : std::thread::hardware_concurrency() / 2;
		thwcc = thwcc > one_vec_sigs.size() / 4 ? (unsigned int)one_vec_sigs.size() / 4 : thwcc;
		if (thwcc == 0) thwcc = 1;
		sigs = FUNCTIONS::splitVector(one_vec_sigs, thwcc);
		FUNCTIONS::log("Best deduced thread count for PLG1: " + std::to_string(thwcc) + "\n", TYPES::PLG1, 1);

		TYPES::HOOK::OD::od_dFunction = (TYPES::HOOK::OD::OodleLZ_Decompress)FUNCTIONS::od_decompress_wait();
		if (MH_CreateHook((void**)INTERNAL::TYPES::HOOK::OD::od_dFunction, &INTERNAL::TYPES::HOOK::OD::OODLE_DECOMPRESS_HOOK,
			(void**)&INTERNAL::TYPES::HOOK::OD::od_function) != MH_OK) {
			FUNCTIONS::log("Unable to hook Oodle_LZDecompress\n", PLG1_ERROR, 2);
		}
		FUNCTIONS::log("Hooked Oodle_LZDecompress\n", PLG1, 1);
	}

	//PLG2
	{
		using namespace INTERNAL::TYPES::GLOBALS::PLG2;
		FUNCTIONS::log(DESIGN::plg2 + "\n\n", TYPES::NONE, 0, 14);
		(void)_mkdir(".\\plugins\\PacketLoader\\PLG2Packets");
		FUNCTIONS::get_loader_entries_G2();
		thwcc = std::thread::hardware_concurrency() == 0 ? 1 : std::thread::hardware_concurrency() / 2;
		thwcc = thwcc > one_vec_sigs.size() / 4 ? (unsigned int)one_vec_sigs.size() / 4 : thwcc;
		if (thwcc == 0) thwcc = 1;
		sigs = FUNCTIONS::splitVector(one_vec_sigs, thwcc);
		FUNCTIONS::log("Best deduced thread count for PLG2: " + std::to_string(thwcc) + "\n", TYPES::PLG2, 1);

		if (MH_CreateHook((void**)INTERNAL::TYPES::HOOK::MLR::mlr_dFunction, &INTERNAL::TYPES::HOOK::MLR::MAIN_LOADING_ROUTINE_HOOK,
			(void**)&INTERNAL::TYPES::HOOK::MLR::mlr_function) != MH_OK) {
			FUNCTIONS::log("Unable to hook Main_Loading_Routine\n", PLG2_ERROR, 2);
		}
		FUNCTIONS::log("Hooked Main_Loading_Routine\n", PLG2, 1);
	}

	FUNCTIONS::log(DESIGN::starting + "\n\n", TYPES::NONE, 0, 12);


	if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
		FUNCTIONS::log("Unable to enable the hooks\n", ERROR, 2);
	}

	for (;;) Sleep(100);
	MH_DisableHook(MH_ALL_HOOKS);
	FreeLibraryAndExitThread((HMODULE)param, 0);
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpvReserved)
{
	switch (fdwReason) {
	case DLL_PROCESS_ATTACH:
		CreateThread(NULL, NULL, MainThread, hModule, NULL, NULL);
		break;
	default:
		break;
	}
	return TRUE;
}

