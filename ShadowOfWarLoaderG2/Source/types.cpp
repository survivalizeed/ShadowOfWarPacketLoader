#include "pch.h"


namespace INTERNAL::TYPES {

	namespace SIGNATURES {
		const char* mlr_signature = "48 8B C4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20 41 56 48 83 EC 20 80 79 30 00 4C 8B F2 41 8B E8";
		const char* l4c_signature = "48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 20 83 61 48 00 48 8D 79 50 83 61 44 00 48 8B D9 48 8B CF E8 ? ? ? ? 84 C0 75 06 ";
	}

	namespace HOOK {
		namespace MLR {
			MAIN_LOADING_ROUTINE mlr_function = NULL;
			MAIN_LOADING_ROUTINE mlr_dFunction = (MAIN_LOADING_ROUTINE)FUNCTIONS::scan_pattern(SIGNATURES::mlr_signature);

			LOAD_4_CHUNKS l4c_function = (LOAD_4_CHUNKS)FUNCTIONS::scan_pattern(SIGNATURES::l4c_signature);
		}
		namespace OD {
			OodleLZ_Decompress od_function = NULL;
			OodleLZ_Decompress od_dFunction; // Initialized in dllmain.cpp. Didn't work here for some reason...
		}
	}

	namespace MAGICS {
		std::vector<BYTE> EMBB = { 0x45, 0x4D, 0x42, 0x42 };
		std::vector<BYTE> BNDL = { 0x42, 0x4E, 0x44, 0x4C };
		std::vector<BYTE> GADB = { 0x47, 0x41, 0x44, 0x42 };
		std::vector<BYTE> SKDB = { 0x53, 0x4B, 0x44, 0x42 };
		std::vector<BYTE> VEGG = { 0x56, 0x45, 0x47, 0x47 };
		std::vector<BYTE> VEGT = { 0x66, 0x45, 0x47, 0x54 };
		std::vector<BYTE> OBJR = { 0x4F, 0x42, 0x4A, 0x52 };
		std::vector<BYTE> LTMI = { 0x4C, 0x54, 0x4D, 0x49 };
		std::vector<BYTE> SRHR = { 0x53, 0x52, 0x48, 0x52 };
		std::vector<BYTE> TEXR = { 0x54, 0x45, 0x58, 0x52 };
		std::vector<BYTE> ANIX = { 0x41, 0x4E, 0x49, 0x58 };
		std::vector<BYTE> MMSH = { 0x4D, 0x4D, 0x53, 0x48 };
		std::vector<BYTE> SKEL = { 0x53, 0x4B, 0x45, 0x4C };
		std::vector<BYTE> HKAI = { 0x48, 0x4B, 0x41, 0x49 };
		std::vector<BYTE> PRFB = { 0x50, 0x52, 0x46, 0x42 };
		std::vector<BYTE> SCRI = { 0x53, 0x43, 0x52, 0x49 };
		std::vector<BYTE> TERR = { 0x54, 0x45, 0x52, 0x52 };
		std::vector<BYTE> UISH = { 0x55, 0x49, 0x53, 0x48 };
		std::vector<BYTE> UIWD = { 0x55, 0x49, 0x57, 0x44 };
		std::vector<BYTE> WDSC = { 0x57, 0x44, 0x53, 0x43 };
		std::vector<BYTE> VIDO = { 0x56, 0x49, 0x44, 0x4F };
		std::vector<BYTE> SUBB = { 0x53, 0x55, 0x42, 0x42 };
		std::vector<BYTE> LTFX = { 0x4C, 0x54, 0x46, 0x58 };
		std::vector<BYTE> TEXA = { 0x54, 0x45, 0x58, 0x41 };
		std::vector<BYTE>  GFX = { 0x47, 0x46, 0x58, 0x08 };
		std::vector<BYTE> LTTA = { 0x4C, 0x54, 0x54, 0x41 };
		std::vector<BYTE> CRES = { 0x43, 0x52, 0x45, 0x53 };
		std::vector<BYTE> MESH = { 0x4D, 0x45, 0x53, 0x48 };
		std::vector<BYTE> BKHD = { 0x42, 0x4B, 0x48, 0x44 };
		std::vector<BYTE> CPUT = { 0x43, 0x50, 0x55, 0x54 };
		std::vector<BYTE> PARA = { 0x50, 0x41, 0x52, 0x41 };
		std::vector<BYTE> RCVA = { 0x52, 0x43, 0x56, 0x41 };
		std::vector<BYTE> SMAP = { 0x53, 0x4D, 0x41, 0x50 };
		std::vector<BYTE> LTAR = { 0x4C, 0x54, 0x41, 0x52 };
		std::vector<BYTE> KB2j = { 0x4B, 0x42, 0x32, 0x6A };
		std::vector<BYTE> BIKi = { 0x42, 0x49, 0x4B, 0x69 };
		std::vector<BYTE> AKPK = { 0x41, 0x4B, 0x50, 0x4B };

		std::vector<std::vector<BYTE>> MAGICS =
		{
			EMBB, BNDL, GADB, SKDB, VEGG, VEGT, OBJR, LTMI, SRHR, TEXR, ANIX, MMSH, SKEL, HKAI, PRFB,
			SCRI, TERR, UISH, UIWD, WDSC, VIDO, SUBB, LTFX, TEXA,  GFX, LTTA, CRES, MESH, BKHD, CPUT,
			PARA, RCVA, SMAP, LTAR, KB2j, BIKi, AKPK
		};

	}

	namespace GLOBALS {
		bool debug;
		bool dump_all;
		bool extract;
		bool re_construct;

		HWND console;
		HANDLE ch;

		Cache cache;

		// untouched
		namespace PLG1 {
			std::vector<TYPES::PLG1_::Data> one_vec_sigs;
			std::vector<std::vector<TYPES::PLG1_::Data>> sigs;

			std::vector<std::vector<BYTE>> exchangedata;

			std::set<std::vector<BYTE>> cachesigs;

			unsigned int thwcc;

			std::atomic<unsigned int> chunks_checked;
		}

		namespace PLG2 {
			std::vector<TYPES::PLG2_::FindData> one_vec_sigs;
			std::vector<std::vector<TYPES::PLG2_::FindData>> sigs;

			std::vector<TYPES::PLG2_::ReplaceData> exchangedata;

			std::set<std::vector<BYTE>> cachesigs;

			unsigned int thwcc;

			std::atomic<unsigned int> chunks_checked;
		}
	}
}