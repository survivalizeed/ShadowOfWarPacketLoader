#pragma once
#include "../pch.h"

namespace INTERNAL::FUNCTIONS {

	template<typename T> requires std::integral<T>
	inline std::string to_hexStr(T t) {
		std::stringstream ss;
		ss << std::hex << t;
		return ss.str();
	}

	inline void log(const std::string& msg, TYPES::Message type, int layer, int color = 7) {
		using namespace TYPES::GLOBALS;
		std::string construct;
		switch (type)
		{
		case TYPES::PLG1:
			construct = "PLG1";
			break;
		case TYPES::PLG2:
			construct = "PLG2";
			break;
		case TYPES::PLG1_ERROR:
			construct = "PLG1-ERROR";
			break;
		case TYPES::PLG2_ERROR:
			construct = "PLG2-ERROR";
			break;
		case TYPES::ERROR:
			construct = "ERROR";
			break;
		default:
			break;
		}

		switch (layer)
		{
		case 0:
			oc(ch, color);
			std::cout << msg;
			return;
		case 1:
			oc(ch, 6);
			std::cout << "[" + construct + "]~~~~~~~~~> ";
			break;
		case 2:
			oc(ch, 3);
			std::cout << "[" + construct + "]~~~~~~~~~~~~~~~~> ";
			break;
		case 3:
			oc(ch, 4);
			std::cout << "[" + construct + "]~~~~~~~~~~~~~~~~~~~~~~~> ";
			break;
		case 4:
			oc(ch, 2);
			std::cout << "[" + construct + "]~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~> ";
			break;
		default:
			break;
		}
		oc(ch, 7);
		std::cout << msg;
	}

	inline uintptr_t od_decompress_wait() {
#pragma warning(disable: 6387)
		while (GetProcAddress(GetModuleHandleA("oo2core_5_win64.dll"), "OodleLZ_Decompress") == nullptr) Sleep(10);
		return (uintptr_t)GetProcAddress(GetModuleHandleA("oo2core_5_win64.dll"), "OodleLZ_Decompress");
	}

	//inline bool detect_whitelisted_path(const std::string& path) {
	//	static std::vector<std::string> whitelist = {
	//		".\\plugins\\Loader\\Signatures",
	//		".\\plugins\\Loader\\Dumps"
	//	};
	//	for (auto& iter : whitelist)
	//		if (path == iter)
	//			return true;
	//	return false;
	//}

	inline void removeBlacklistFromVector(std::vector<fs::path>& vector) {
		for (int i = 0; i < vector.size(); ++i) {
			if (vector[i].string().ends_with("__folder_managed_by_vortex"))
				vector.erase(vector.begin() + i);
		}
	}

	inline bool compareByIndex(const fs::path& a, const fs::path& b) {
		int aVal = 0;
		size_t lastBackslash = a.string().find_last_of("\\");
		if (lastBackslash != std::string::npos) {
			auto filename = a.string().substr(lastBackslash + 1);
			size_t dotPos = filename.find_last_of(".");
			if (dotPos != std::string::npos) {
				filename = filename.substr(0, dotPos);
				aVal = std::stoi(filename);
			}
		}
		int bVal = 0;
		lastBackslash = b.string().find_last_of("\\");
		if (lastBackslash != std::string::npos) {
			auto filename = b.string().substr(lastBackslash + 1);
			size_t dotPos = filename.find_last_of(".");
			if (dotPos != std::string::npos) {
				filename = filename.substr(0, dotPos);
				bVal = std::stoi(filename);
			}
		}
		return aVal < bVal;
	}

	inline std::vector<BYTE> read_block(std::uint32_t offset, std::uint32_t length, const std::string& filename) {
		std::ifstream is(filename, std::ios::binary);
		is.seekg(offset);
		std::vector<BYTE> data(length);
		is.read(reinterpret_cast<char*>(data.data()), length);
		data.resize(is.gcount());
		return data;
	}


	inline void terminate(TYPES::Message m) {
		FUNCTIONS::log("Terminating in 10 seconds...\n", m, 3);
		Sleep(10000);
		exit(-1);
	}

	inline bool containsFlag(const std::string& file_name, const std::string& section, const std::string& constant) {
		std::ifstream file(file_name);
		std::string line;
		bool found = false;
		while (std::getline(file, line)) {
			if (line.front() == '[' && line.back() == ']')
				if (found)
					break;
				else if (line.substr(1, line.size() - 2) == section)
					found = true;
			if (found && line == constant)
				return true;
		}
		return false;
	}

	inline void get_loader_entries_G1() {
		using namespace INTERNAL::TYPES::GLOBALS::PLG1;

		(void)_mkdir(".\\plugins\\PacketLoader\\Internal\\PLG1");
		(void)_mkdir(".\\plugins\\PacketLoader\\Internal\\PLG1\\Signatures");
		for (const auto& entry : fs::directory_iterator(".\\plugins\\PacketLoader\\Internal\\PLG1\\Signatures")) {
			if (entry.path().string() != "__folder_managed_by_vortex")
				cachesigs.insert(read_block(0, 1000, entry.path().string()));
		}
		FUNCTIONS::log("Collected " + std::to_string(cachesigs.size()) + " signatures\n", TYPES::PLG1, 1);

		for (const auto& entry : fs::directory_iterator(".\\plugins\\PacketLoader\\PLG1Packets")) {
			if (entry.is_directory() && !fs::is_empty(entry)) {
				using namespace std;
				log("Searching in " + entry.path().string() + "\n", TYPES::PLG1, 1);
				mINI::INIFile file(entry.path().string() + "\\Config.ini");
				mINI::INIStructure ini;
					
				if (!file.read(ini)) {
					log("Unable to find " + entry.path().string() + "\\Config.ini\n", TYPES::PLG1_ERROR, 2);
					FUNCTIONS::terminate(TYPES::PLG1_ERROR);
				}
				
				auto subfolder = entry.path().string() + "\\Find";
				int counter = 1;
				if (!fs::exists(subfolder)) {
					log("Unable to find " + subfolder + "\n", TYPES::PLG1_ERROR, 2);
					FUNCTIONS::terminate(TYPES::PLG1_ERROR);
				}
				std::vector<fs::path> files_in_find_directory;
				std::copy(fs::directory_iterator(subfolder), fs::directory_iterator(), std::back_inserter(files_in_find_directory));
				std::sort(files_in_find_directory.begin(), files_in_find_directory.end(), compareByIndex);
				removeBlacklistFromVector(files_in_find_directory);

				auto section = to_string(counter);

				for (const auto& findEntry : files_in_find_directory) {	
					log("Reading " + findEntry.string() + "\n", TYPES::PLG1, 2);
					if (!ini.has(section)) {
						log("Unable to find [" + section + "] section in the Config.ini\n", TYPES::PLG1_ERROR, 3);
						FUNCTIONS::terminate(TYPES::PLG1_ERROR);
					}
					TYPES::PLG1_::FindData findData;
					findData.path = findEntry.string();
							
					if (containsFlag(entry.path().string() + "\\Config.ini", section, "<<REMOVE>>"))
						findData.remove = true;			
					if (containsFlag(entry.path().string() + "\\Config.ini", section, "<<AUTO>>")) {
						findData.signature = read_block(0, stoi(ini[section]["signature_check_length"]), findEntry.string());
						findData.type = TYPES::PLG1_::Type::Auto;
					}
					else {
						try {
							findData.signature = read_block(stoi(ini[section]["signature_read_offset"]), stoi(ini[section]["signature_check_length"]), findEntry.string());
							findData.safeProperties.signature_read_offset = stoi(ini[section]["signature_read_offset"]);
							findData.safeProperties.signature_check_length = stoi(ini[section]["signature_check_length"]);
							findData.safeProperties.signature_verify_bytes_length = stoi(ini[section]["signature_verify_bytes_length"]);
							findData.type = TYPES::PLG1_::Type::Safe;
						}
						catch (...) {
							log("Section [" + section + "] is not the newest G1 standard. Consider updating the packet!\n", TYPES::PLG1, 4);
							findData.signature = read_block(stoi(ini[section]["signature_read_offset"]), stoi(ini[section]["signature_length"]), findEntry.string());
							findData.safeProperties.signature_read_offset = stoi(ini[section]["signature_read_offset"]);
							findData.safeProperties.signature_check_length = stoi(ini[to_string(counter)]["signature_length"]);
							findData.type = TYPES::PLG1_::Type::Old;
						}
					}

					one_vec_sigs.push_back(findData);
					++counter;
				}
				log("Found " + to_string(counter - 1) + " entries in " + subfolder + "\n", TYPES::PLG1, 1);
				counter = 1;
				subfolder = entry.path().string() + "\\Replace";

				if (!fs::exists(subfolder)) {
					log("Unable to find " + subfolder + "\n", TYPES::PLG1_ERROR, 2);
					FUNCTIONS::terminate(TYPES::PLG1_ERROR);
				}

				std::vector<fs::path> files_in_replace_directory;
				std::copy(fs::directory_iterator(subfolder), fs::directory_iterator(), std::back_inserter(files_in_replace_directory));
				std::sort(files_in_replace_directory.begin(), files_in_replace_directory.end(), compareByIndex);
				removeBlacklistFromVector(files_in_replace_directory);

				for (const auto& replaceEntry : files_in_replace_directory) {
					using namespace std;
					log("Reading " + replaceEntry.string() + "\n", TYPES::PLG1, 2);

					TYPES::PLG1_::ReplaceData replaceData;
					replaceData.path = replaceEntry.string();
					
					if (ini[section].has("exchange_data_read_offset")) {
						replaceData.safeProperties.exchange_data_read_offset = stoi(ini[section]["exchange_data_read_offset"]);
						replaceData.safeProperties.exchange_data_length = stoi(ini[section]["exchange_data_length"]);
					}
				
					exchangedata.push_back(replaceData);
					++counter;
				}
				log("Found " + to_string(counter - 1) + " entries in " + subfolder + "\n\n", TYPES::PLG1, 1);
			}
		}
	}

	inline void get_loader_entries_G2() {
		using namespace INTERNAL::TYPES::GLOBALS::PLG2;
		

		(void)_mkdir(".\\plugins\\PacketLoader\\Internal\\PLG2");
		(void)_mkdir(".\\plugins\\PacketLoader\\Internal\\PLG2\\Signatures");
		for (const auto& entry : fs::directory_iterator(".\\plugins\\PacketLoader\\Internal\\PLG2\\Signatures")) {
			if (entry.path().string() != "__folder_managed_by_vortex")
				cachesigs.insert(read_block(0, 1000, entry.path().string()));
		}
		FUNCTIONS::log("Collected " + std::to_string(cachesigs.size()) + " signatures\n", TYPES::PLG2, 1);
		
		for (const auto& entry : fs::directory_iterator(".\\plugins\\PacketLoader\\PLG2Packets")) {
			if (entry.is_directory() && !fs::is_empty(entry)) {
				using namespace std;
				log("Searching in " + entry.path().string() + "\n", TYPES::PLG2, 1);
				mINI::INIFile file(entry.path().string() + "\\Config.ini");
				mINI::INIStructure ini;
				if (!file.read(ini)) {
					log("Unable to find " + entry.path().string() + "\\Config.ini\n", TYPES::PLG2_ERROR, 2);
					FUNCTIONS::terminate(TYPES::PLG2_ERROR);
				}
				auto subfolder = entry.path().string() + "\\Find";
				int counter = 1;
				if (!fs::exists(subfolder)) {
					log("Unable to find " + subfolder + "\n", TYPES::PLG2_ERROR, 2);
					FUNCTIONS::terminate(TYPES::PLG2_ERROR);
				}
				std::vector<fs::path> files_in_find_directory;
				std::copy(fs::directory_iterator(subfolder), fs::directory_iterator(), std::back_inserter(files_in_find_directory));
				std::sort(files_in_find_directory.begin(), files_in_find_directory.end(), compareByIndex);
				removeBlacklistFromVector(files_in_find_directory);
				for (const auto& findEntry : files_in_find_directory) {
					log("Reading " + findEntry.string() + "\n", TYPES::PLG2, 2);
					if (!ini.has(to_string(counter))) {
						log("Unable to find [" + to_string(counter) + "] section in the Config.ini\n", TYPES::PLG2_ERROR, 3);
						FUNCTIONS::terminate(TYPES::PLG2_ERROR);
					}
					TYPES::PLG2_::FindData data;
					data.signature = read_block(0, stoi(ini[to_string(counter)]["signature_check_length"]), findEntry.string());
					data.path = findEntry.string();
					data.size_emulation = (bool)stoi(ini[to_string(counter)]["size_emulation"]);
					one_vec_sigs.push_back(data);
					++counter;
				}
				log("Found " + to_string(counter - 1) + " entries in " + subfolder + "\n", TYPES::PLG2, 1);
				counter = 1;
				subfolder = entry.path().string() + "\\Replace";
				if (!fs::exists(subfolder)) {
					log("Unable to find " + subfolder + "\n", TYPES::PLG2_ERROR, 2);
					FUNCTIONS::terminate(TYPES::PLG2_ERROR);
				}
				std::vector<fs::path> files_in_replace_directory;
				std::copy(fs::directory_iterator(subfolder), fs::directory_iterator(), std::back_inserter(files_in_replace_directory));
				std::sort(files_in_replace_directory.begin(), files_in_replace_directory.end(), compareByIndex);
				removeBlacklistFromVector(files_in_replace_directory);
				for (const auto& replaceEntry : files_in_replace_directory) {
					using namespace std;
					log("Reading " + replaceEntry.string() + "\n", TYPES::PLG2, 2);
					TYPES::PLG2_::ReplaceData data;
					data.path = replaceEntry.string();
					exchangedata.push_back(data);
					++counter;
				}
				log("Found " + to_string(counter - 1) + " entries in " + subfolder + "\n\n", TYPES::PLG2, 1);
			}
		}
	}

	inline void write_file_binary(std::string const& filename, void* ptr, size_t const size)
	{
		std::ofstream file(filename, std::ios::binary);
		file.write((const char*)ptr, size);
		file.close();
	}

	inline std::vector<std::vector<TYPES::PLG1_::FindData>> splitVector(const std::vector<TYPES::PLG1_::FindData>& inputVector, size_t N) {
		std::vector<std::vector<TYPES::PLG1_::FindData>> ret;
		size_t nLimit = ceil((double)inputVector.size() / N);
		auto start = inputVector.begin();
		for (size_t i = 0; i < inputVector.size(); i += nLimit) {
			std::vector<TYPES::PLG1_::FindData> v(start + i, start + std::min<size_t>(i + nLimit, inputVector.size()));
			ret.push_back(v);
		}
		return ret;
	}

	inline std::vector<std::vector<TYPES::PLG2_::FindData>> splitVector(const std::vector<TYPES::PLG2_::FindData>& inputVector, size_t N) {
		std::vector<std::vector<TYPES::PLG2_::FindData>> ret;
		size_t nLimit = ceil((double)inputVector.size() / N);
		auto start = inputVector.begin();
		for (size_t i = 0; i < inputVector.size(); i += nLimit) {
			std::vector<TYPES::PLG2_::FindData> v(start + i, start + std::min<size_t>(i + nLimit, inputVector.size()));
			ret.push_back(v);
		}
		return ret;
	}

	inline std::string getFileName(const std::string& filePath) {
		fs::path path(filePath);
		return path.filename().string();
	}

	inline void refreshTitle() {
		using namespace INTERNAL::TYPES::GLOBALS;
		for (;;) {
			std::string dbgStr = "";
			std::string cacheStr = "";
			std::string dmpaStr = "";
			std::string reConStr = "";
			if (debug)
				dbgStr = "Debug: On";
			else
				dbgStr = "Debug: Off";
			if (cache == TYPES::generate)
				cacheStr = "Signatures: Generate";
			else
				cacheStr = "Signatures: Read";
			if (dump_all)
				dmpaStr = "Dump all: On";
			else
				dmpaStr = "Dump all: Off";
			if (re_construct)
				reConStr = "Re-Construct: On";
			else
				reConStr = "Re-Construct: Off";
			SetWindowTextA(console, std::string("SoWPL:> " + cacheStr + "  " + dbgStr + "  " + dmpaStr + "  " + reConStr + "   |   PLG1:> Chunks checked : " + 
				std::to_string(PLG1::chunks_checked) + "  Thread count: " + std::to_string(PLG1::thwcc) + "   |   PLG2:> Chunks checked: " + 
				std::to_string(PLG2::chunks_checked) + "  Thread count: " + std::to_string(PLG2::thwcc)).c_str());
			Sleep(1);
		}
	}


	inline uintptr_t searchPatternInMemory(const TYPES::PLG1_::FindData& pattern, const unsigned char* startAddress, const unsigned char* endAddress) {
		if (startAddress == nullptr) return 0;
		for (uintptr_t address = (uintptr_t)startAddress; address < (uintptr_t)endAddress - pattern.signature.size() + 1; ++address) {
			if (std::memcmp((const void*)address, (const void*)(pattern.signature.data()), pattern.signature.size()) == 0) {
				return address;
			}
		}
		return 0;
	}

	inline uintptr_t searchPatternInMemory(const TYPES::PLG2_::FindData& pattern, const unsigned char* startAddress, const unsigned char* endAddress) {
		if (startAddress == nullptr) return 0;
		for (uintptr_t address = (uintptr_t)startAddress; address < (uintptr_t)endAddress - pattern.signature.size() + 1; ++address) {
			if (std::memcmp((const void*)address, (const void*)(pattern.signature.data()), pattern.signature.size()) == 0) {
				return address;
			}
		}
		return 0;
	}

	inline std::optional<uintptr_t> searchPatternInMemory(const std::vector<BYTE>& pattern, const unsigned char* startAddress, const unsigned char* endAddress) {
		if (startAddress == nullptr) return std::nullopt;
		for (uintptr_t address = (uintptr_t)startAddress; address < (uintptr_t)endAddress - pattern.size() + 1; ++address) {
			if (std::memcmp((const void*)address, (const void*)(pattern.data()), pattern.size()) == 0) {
				return address;
			}
		}
		return std::nullopt;
	}

	inline uintptr_t scan_pattern(const char* signature) {
		auto pattern_to_byte = [](const char* pattern) {
				auto bytes = std::vector<char>{};
				auto start = const_cast<char*>(pattern);
				auto end = const_cast<char*>(pattern) + strlen(pattern);

				for (auto current = start; current < end; ++current) {
					if (*current == '?') {
						++current;
						if (*current == '?')
							++current;
						bytes.push_back('\?');
					}
					else {
						bytes.push_back(strtoul(current, &current, 16));
					}
				}
				return bytes;
		};

		MODULEINFO info;
		GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(NULL), &info, sizeof(MODULEINFO));
		uintptr_t base = (uintptr_t)GetModuleHandleA(NULL);
		uintptr_t sizeOfImage = (uintptr_t)info.SizeOfImage;
		auto patternBytes = pattern_to_byte(signature);

		uintptr_t patternLength = patternBytes.size();
		auto data = patternBytes.data();

		for (uintptr_t i = 0; i < sizeOfImage - patternLength; i++) {
			bool found = true;
			for (uintptr_t j = 0; j < patternLength; j++) {
				char a = '\?';
				char b = *(char*)(base + i + j);
				found &= data[j] == a || data[j] == b;
			}
			if (found) {
				return base + i;
			}
		}
		return NULL;
	}


}