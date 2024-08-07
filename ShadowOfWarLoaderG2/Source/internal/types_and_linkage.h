#pragma once
#include "../pch.h"

namespace INTERNAL::TYPES {

    struct File {
        __int64 handle_ptr;
        __int64(*read_file_callback)(File*, __int64, __int64);
        BYTE offset1[8];
        __int64 file_offset;
        BYTE offset2[8];
        __int64 EMBB_size;
        bool file_read;
        BYTE offset3[7];
        __int64 source_ptr;
        BYTE offset4[4];
        DWORD currently_loaded_size;
        DWORD file_relative_offset;
    };

#pragma warning(disable: 26495)
	namespace PLG1_ {
		struct Data {
			std::string path;
			std::vector<BYTE> bytes;
			unsigned int siglen = 0;
			bool old = false;
			int debug_index = 0;
		};
	}

	namespace PLG2_ {
		struct FindData {
			std::string path;
			std::vector<BYTE> bytes;
			std::vector<BYTE> signature;
			int debug_index = 0;
			int reconstruct_index = 0;
			bool size_emulation = false;
		};

		struct ReplaceData {
			std::string path;
			std::vector<BYTE> bytes;
		};
	}

	enum Cache {
		generate,
		read
	};

#undef ERROR
	enum Message {
		PLG1,
		PLG2,
		PLG1_ERROR,
		PLG2_ERROR,
		ERROR,
		NONE
	};

	namespace SIGNATURES {
		extern const char* mlr_signature;
		extern const char* l4c_signature;
	}

	namespace HOOK {
		namespace MLR {
			typedef __int64(__fastcall* MAIN_LOADING_ROUTINE)(File*, char*, size_t);
			extern MAIN_LOADING_ROUTINE mlr_function;
			extern MAIN_LOADING_ROUTINE mlr_dFunction;

			typedef char(__fastcall* LOAD_4_CHUNKS)(File*);
			extern LOAD_4_CHUNKS l4c_function;
		}
		namespace OD {
			typedef int(__fastcall* OodleLZ_Decompress)(uintptr_t, unsigned int, uintptr_t, unsigned int, int, int, int, void*, void*, void*, void*, void*, void*, int);
			extern OodleLZ_Decompress od_function;
			extern OodleLZ_Decompress od_dFunction;
		}
	}

    namespace MAGICS {
		extern std::vector<BYTE> EMBB;
		extern std::vector<BYTE> BNDL;
		extern std::vector<BYTE> GADB;
		extern std::vector<BYTE> SKDB;
		extern std::vector<BYTE> VEGG;
		extern std::vector<BYTE> VEGT;
		extern std::vector<BYTE> OBJR;
		extern std::vector<BYTE> LTMI;
		extern std::vector<BYTE> SRHR;
		extern std::vector<BYTE> TEXR;
		extern std::vector<BYTE> ANIX;
		extern std::vector<BYTE> MMSH;
		extern std::vector<BYTE> SKEL;
		extern std::vector<BYTE> HKAI;
		extern std::vector<BYTE> PRFB;
		extern std::vector<BYTE> OBJR;
		extern std::vector<BYTE> SCRI;
		extern std::vector<BYTE> TERR;
		extern std::vector<BYTE> UISH;
		extern std::vector<BYTE> UIWD;
		extern std::vector<BYTE> WDSC;
		extern std::vector<BYTE> VIDO;
		extern std::vector<BYTE> SUBB;
		extern std::vector<BYTE> LTFX;
		extern std::vector<BYTE> TEXA;
		extern std::vector<BYTE>  GFX;
		extern std::vector<BYTE> LTTA;
		extern std::vector<BYTE> CRES;
		extern std::vector<BYTE> MESH;
		extern std::vector<BYTE> BKHD;
		extern std::vector<BYTE> CPUT;
		extern std::vector<BYTE> PARA;
		extern std::vector<BYTE> RCVA;
		extern std::vector<BYTE> SMAP;
		extern std::vector<BYTE> LTAR;
		extern std::vector<BYTE> KB2j;
		extern std::vector<BYTE> BIKi;
		extern std::vector<BYTE> AKPK;

		extern std::vector<std::vector<BYTE>> MAGICS;
    }

	namespace GLOBALS {
		extern bool debug;
		extern bool dump_all;
		extern bool extract;
		extern bool re_construct;

		extern HWND console;
		extern HANDLE ch;

		extern Cache cache;

		// untouched
		namespace PLG1 {
			extern std::vector<TYPES::PLG1_::Data> one_vec_sigs;
			extern std::vector<std::vector<TYPES::PLG1_::Data>> sigs;

			extern std::vector<std::vector<BYTE>> exchangedata;

			extern std::set<std::vector<BYTE>> cachesigs;

			extern unsigned int thwcc;

			extern std::atomic<unsigned int> chunks_checked;
		}

		namespace PLG2 {
			extern std::vector<TYPES::PLG2_::FindData> one_vec_sigs;
			extern std::vector<std::vector<TYPES::PLG2_::FindData>> sigs;

			extern std::vector<TYPES::PLG2_::ReplaceData> exchangedata;

			extern std::set<std::vector<BYTE>> cachesigs;

			extern unsigned int thwcc;

			extern std::atomic<unsigned int> chunks_checked;
		}
	}
}

namespace DESIGN {
	extern std::string name;
	extern std::string plg1;
	extern std::string plg2;
	extern std::string starting;
}