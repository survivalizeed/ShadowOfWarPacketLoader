#pragma once
#include "../pch.h"


namespace INTERNAL::TYPES::HOOK {

	namespace MLR {
		inline __int64 __fastcall MAIN_LOADING_ROUTINE_HOOK(File* file, char* outVar, size_t bytes_to_read) {
			using namespace INTERNAL::TYPES::GLOBALS::PLG2;
			using namespace INTERNAL::TYPES::GLOBALS;
			
			static bool found = false, limit = false, readjustRelOffset = false, onceNotify = false, chunk_changed = false, invalid = false, loadOnce = false,
				done = false, activeChunk = false, fullfind = false, invalidChunkCheckOnce = false, notifyReconstructOnce = false;
			static unsigned int datawritten = 1, dump_chunks_counter = 1, snaprelFileOffset = 0, reconstructReadCount = 0;
			static uintptr_t dataIndex = 0, index = 0, address = 0;
			static std::ofstream cacheFileWrite, reconstructFile;
			static std::string debugStr, dump_allStr, currentDebugFile, invalidpath = "";
			
			static uintptr_t address_backup = 0;


			auto initFoundState = [&]() -> void {
				found = true;
				snaprelFileOffset = 0;
				chunk_changed = false;
				address_backup = address;
				address = 0;
				invalidChunkCheckOnce = true;
			};

			auto deleteLoaded = [&]() -> void {
				std::vector<BYTE>().swap(one_vec_sigs[index].bytes);
				std::vector<BYTE>().swap(exchangedata[index].bytes);
				loadOnce = false;
			};

			char* destination;
			unsigned int bytes_to_read2;
			char* outVarRef;
			unsigned int size;


			destination = outVar;
			bytes_to_read2 = bytes_to_read;
			if (file->file_read) {
				bytes_to_read = (DWORD)bytes_to_read;
				outVarRef = outVar;
			exit:
				memset(outVarRef, 0, bytes_to_read);
				return 1;
			}
			if (bytes_to_read) {
				for (;;) {

					if (file->file_relative_offset == file->currently_loaded_size && !limit) {
						
						l4c_function(file);

						chunks_checked++;
						
						if (cache == read && !activeChunk) {
							std::vector<BYTE> chunk_signature;
							for (int i = 0; i < 1000; ++i)
								chunk_signature.push_back(*(uintptr_t*)(file->source_ptr + i));
							for (const auto& iter : cachesigs) {
								if (iter == chunk_signature)
									goto good;
							}
							goto noSigFound;
						}
					good:;

						chunk_changed = true;


						if (activeChunk && found) {
							FUNCTIONS::log("Ignoring this chunk (h): " + FUNCTIONS::to_hexStr(file->source_ptr) + " - "
								+ FUNCTIONS::to_hexStr(file->source_ptr + file->currently_loaded_size) + "\n", TYPES::PLG2, 2);

							if (debug) {
								FUNCTIONS::write_file_binary(currentDebugFile + "\\" + std::to_string(dump_chunks_counter) + ".dmp", (void*)file->source_ptr, file->currently_loaded_size);
								dump_chunks_counter++;
							}
						}

						if (!activeChunk && !one_vec_sigs.empty()) {
							std::vector<std::thread> threads(thwcc - 1);
							auto searchThreadFunc = [&](const std::vector<TYPES::PLG2_::FindData>& sigs) {
								int idx = 0;
								uintptr_t local_address = 0;
								while (local_address == 0 && idx < sigs.size()) {
									local_address = FUNCTIONS::searchPatternInMemory(sigs[idx], (const unsigned char*)file->source_ptr,
										(const unsigned char*)(file->source_ptr + file->currently_loaded_size));
									if (local_address != 0) {
										for (int i = 0; i < one_vec_sigs.size(); ++i) {
											if (sigs[idx].signature == one_vec_sigs[i].signature && invalidpath != sigs[idx].path) {
												index = i;
												address = local_address;
											}
										}
									}
									idx++;
								}
							};
							
							for (int i = 0; i < (int)thwcc - 1; i++) {
								threads[i] = std::thread(searchThreadFunc, std::cref(sigs[i]));
							}
							searchThreadFunc(sigs[sigs.size() - 1]);
							for (auto& thread : threads) {
								thread.join();
							}
							
							invalidpath = "";
						}
						if (address == 0 && !activeChunk)
							index = 0;
						if (address != 0 && !activeChunk) {

							if (cache == generate) {
								std::vector<BYTE> chunk_signature;
								for (int i = 0; i < 1000; ++i)
									chunk_signature.push_back(*(uintptr_t*)(file->source_ptr + i));

								auto hash = std::hash<std::string>{}(one_vec_sigs[index].path + std::to_string(chunks_checked));

								bool signatureExists = false;
								for (auto& iter : cachesigs) {
									if (iter == chunk_signature) {
										signatureExists = true;
										break;
									}
								}

								if (!signatureExists) {
									cacheFileWrite.open(".\\plugins\\PacketLoader\\Internal\\PLG2\\Signatures\\" + std::to_string(hash) + ".sig", std::ios::binary);
									cacheFileWrite.write((const char*)chunk_signature.data(), chunk_signature.size());
									cacheFileWrite.close();
									cachesigs.insert(chunk_signature);
								}
							}
							FUNCTIONS::log("Found data count (d): " + std::to_string(datawritten) + "\n", TYPES::PLG2, 1);
							FUNCTIONS::log("File: " + one_vec_sigs[index].path + "\n", TYPES::PLG2, 1);
							FUNCTIONS::log("Chunk start (h): " + FUNCTIONS::to_hexStr(file->source_ptr) + "\n", TYPES::PLG2, 1);
							FUNCTIONS::log("Found data at (h): " + FUNCTIONS::to_hexStr(address) + "\n", TYPES::PLG2, 1);
							FUNCTIONS::log("Chunk end (h): " + FUNCTIONS::to_hexStr(file->source_ptr + file->currently_loaded_size) + "\n", TYPES::PLG2, 1);
							FUNCTIONS::log("Bytes left in chunk (d): " + std::to_string(file->currently_loaded_size - (address - file->source_ptr)) + "\n",
								TYPES::PLG2, 1);
							FUNCTIONS::log("Chunks checked (d): " + std::to_string(chunks_checked) + "\n", TYPES::PLG2, 1);

							if (debug) {
								dump_chunks_counter = 1;
								FUNCTIONS::log("Debug mode is enabled...\n", TYPES::PLG2, 2);
								FUNCTIONS::log("Dumping the chunks and their respective subsequent ones until fully overwritten or identified as invalid\n", TYPES::PLG2, 2);
								(void)_mkdir(".\\plugins\\PacketLoader\\Internal\\PLG2\\Dumps");
								currentDebugFile = ".\\plugins\\PacketLoader\\Internal\\PLG2\\Dumps\\" +
									FUNCTIONS::getFileName(one_vec_sigs[index].path) + "_" + std::to_string(one_vec_sigs[index].debug_index);
								(void)_mkdir(currentDebugFile.c_str());
								FUNCTIONS::log("Created a folder: " + currentDebugFile + "\n", TYPES::PLG1, 2);
								FUNCTIONS::write_file_binary(currentDebugFile + "\\" + std::to_string(dump_chunks_counter) + ".dmp",
									(void*)file->source_ptr, file->currently_loaded_size);			
								FUNCTIONS::log("Place your breakpoints now to do some debugging!\n", TYPES::PLG2, 2);
								FUNCTIONS::log("Press any key in the console window to continue the loading...\n", TYPES::PLG2, 2);
								(void)_getch();
								one_vec_sigs[index].debug_index++;
								dump_chunks_counter++;
							}
							datawritten++;
							activeChunk = true;
						}
					}

				noSigFound:;


					if (file->file_relative_offset >= 4 && address != 0) {
						if ((uintptr_t)(file->source_ptr + (__int64)file->file_relative_offset) == address - 4 && activeChunk && one_vec_sigs[index].size_emulation) {
							FUNCTIONS::log("Routine reached the target data\n", TYPES::PLG2, 1);
							FUNCTIONS::log("Switched the loading buffer\n", TYPES::PLG2, 1);
							fullfind = true;
							initFoundState();
						}
					}
					if ((uintptr_t)(file->source_ptr + (__int64)file->file_relative_offset) == address && activeChunk) {
						FUNCTIONS::log("Routine reached the target data\n", TYPES::PLG2, 1);
						FUNCTIONS::log("Switched the loading buffer\n", TYPES::PLG2, 1);
						initFoundState();
					}


					outVarRef = destination;
					if (file->file_read)
						break;

					size = file->currently_loaded_size - (__int64)file->file_relative_offset;
					if (bytes_to_read2 < size)
						size = bytes_to_read2;

					if (size == 256 && invalidChunkCheckOnce) { // Can be that there is a "skipping load"
						fullfind = false;
						FUNCTIONS::log("Detected a useless Load. Switching back the loading buffer...\n\n", TYPES::PLG2, 2);
						deleteLoaded();
						readjustRelOffset = false;
						chunk_changed = false;
						onceNotify = false;
						limit = false;
						found = false;
						activeChunk = false;
						invalidpath = one_vec_sigs[index].path;
						goto INVALIDCHUNK;
					}
					invalidChunkCheckOnce = false;

					if (found) {
						if (!loadOnce) {
							{
								std::ifstream file(one_vec_sigs[index].path, std::ios::binary | std::ios::ate);
								std::streamsize size = file.tellg();
								file.seekg(0, std::ios::beg);
								std::vector<BYTE> tmp(size);
								file.read((char*)tmp.data(), size);
								one_vec_sigs[index].bytes = tmp;

							}
							file->EMBB_size -= one_vec_sigs[index].bytes.size();

							{
								std::ifstream file(exchangedata[index].path, std::ios::binary | std::ios::ate);
								std::streamsize size = file.tellg();
								file.seekg(0, std::ios::beg);
								std::vector<BYTE> tmp(size);
								file.read((char*)tmp.data(), size);
								exchangedata[index].bytes = tmp;

							}
							file->EMBB_size += exchangedata[index].bytes.size();
							loadOnce = true;
						}
						if (fullfind) {
							if (*(unsigned int*)(file->source_ptr + (__int64)file->file_relative_offset) == (unsigned int)one_vec_sigs[index].bytes.size()) {
								unsigned int edSize = exchangedata[index].bytes.size();
								memcpy(destination, &edSize, size);
							}
							else 
								memcpy(destination, (const void*)(file->source_ptr + (__int64)file->file_relative_offset), size);
							fullfind = false;
						}
						else {
							if (re_construct) {
								if (!notifyReconstructOnce) {
									FUNCTIONS::log("Reconstruct mode is enabled...\n", TYPES::PLG2, 2);
									(void)_mkdir(".\\plugins\\PacketLoader\\Internal\\PLG2\\Reconstruct");
									reconstructFile.open(".\\plugins\\PacketLoader\\Internal\\PLG2\\Reconstruct\\" +
										FUNCTIONS::getFileName(one_vec_sigs[index].path) + "_" + std::to_string(one_vec_sigs[index].reconstruct_index) + ".txt");
									one_vec_sigs[index].reconstruct_index++;
									notifyReconstructOnce = true;

									reconstructFile << "Reconstruct file size: " << exchangedata[index].bytes.size() << "\n\n";
								}
								reconstructFile << "Call " << ++reconstructReadCount << " {\n\n";
								reconstructFile << "\tAddress(" << std::hex << (uintptr_t)destination << ")  " << "File offset(" << std::dec << snaprelFileOffset
									<< ")  " << "Size(" << size << ")\n" << "\n\tContent {\n\t\t";
								if (size == 1 || size == 2 || size == 4 || size == 8) {
									reconstructFile << "Datatypes {\n\t\t\t";
									switch (size)
									{
									case 1:
									{
										reconstructFile << "Byte(" << (unsigned int)exchangedata[index].bytes[snaprelFileOffset] << ")";
										break;
									}
									case 2:
									{
										short tmp;
										memcpy(&tmp, exchangedata[index].bytes.data() + snaprelFileOffset, 2);
										reconstructFile << "Short(" << (unsigned int)tmp << ")";
										break;
									}
									case 4:
									{
										unsigned int tmp;
										float tmp2;
										memcpy(&tmp, exchangedata[index].bytes.data() + snaprelFileOffset, 4);
										memcpy(&tmp2, exchangedata[index].bytes.data() + snaprelFileOffset, 4);
										reconstructFile << "Long(" << tmp << ")\n\t\t\tFloat(" << tmp2 << ")";
										break;
									}
									case 8:
									{
										__int64 tmp;
										double tmp2;
										memcpy(&tmp, exchangedata[index].bytes.data() + snaprelFileOffset, 8);
										memcpy(&tmp2, exchangedata[index].bytes.data() + snaprelFileOffset, 8);
										reconstructFile << "Long long(" << tmp << ")\n\t\t\tDouble(" << tmp2 << ")";
										break;
									}
									default:
										break;
									}
									reconstructFile << "\n\t\t}\n\t\t";
								}
								reconstructFile << "Bytes {\n\t\t\t";
								for (int i = 0; i < size; ++i) {
									std::stringstream ss;
									ss << "0x" << std::hex << (int)exchangedata[index].bytes[snaprelFileOffset + i];
									if (ss.str().size() == 3) ss << "0";
									reconstructFile << ss.str() << " ";
									if ((i + 1) % 8 == 0)
										reconstructFile << "\n\t\t\t";
								}
								reconstructFile << "\n\t\t}\n\t\tASCII {\n\t\t\t";
								for (int i = 0; i < size; ++i) {
									std::stringstream ss;
									ss << exchangedata[index].bytes[snaprelFileOffset + i];
									reconstructFile << ss.str();
									if ((i + 1) % 16 == 0)
										reconstructFile << "\n\t\t\t";
								}
								reconstructFile << "\n\t\t}\n\t}\n}\n\n";
							}

							memcpy(destination, (const void*)(exchangedata[index].bytes.data() + snaprelFileOffset), size);

							snaprelFileOffset += size;

							if (snaprelFileOffset >= one_vec_sigs[index].bytes.size()) {
								limit = true;
							}
							if (snaprelFileOffset >= one_vec_sigs[index].bytes.size() && snaprelFileOffset < exchangedata[index].bytes.size() && !onceNotify) {
								FUNCTIONS::log("Reached the limit of the original file size\n", TYPES::PLG2, 2);
								FUNCTIONS::log("Pushing in the remaining data...\n", TYPES::PLG2, 2);
								onceNotify = true;
								readjustRelOffset = true;
							}
							if (snaprelFileOffset >= exchangedata[index].bytes.size()) {
								FUNCTIONS::log("Replace completed\n", TYPES::PLG2, 1);
								FUNCTIONS::log("Switching back to original loading buffer...\n", TYPES::PLG2, 1);
								limit = false;
								found = false;
								activeChunk = false;
								invalidChunkCheckOnce = false;
								if (re_construct) {
									notifyReconstructOnce = false;
									reconstructFile.close();
								}				
								if (!readjustRelOffset) {
									deleteLoaded();
									FUNCTIONS::log("Finished\n\n", TYPES::PLG2, 1);
								}
							}
						}
					}
					else {
						if (readjustRelOffset) {
							FUNCTIONS::log("Readjusting the relative file offset...\n", TYPES::PLG2, 1);
							std::vector<uintptr_t> addresses;
							uintptr_t start = 0;
							uintptr_t end = 0;
							if (chunk_changed) {
								start = file->source_ptr;
								end = file->source_ptr + file->currently_loaded_size;
							}
							else {
								start = address_backup + one_vec_sigs[index].bytes.size();
								end = start + (file->currently_loaded_size - (start - file->source_ptr));
							}
							for (auto& magic : TYPES::MAGICS::MAGICS) {
								std::optional<uintptr_t> val = FUNCTIONS::searchPatternInMemory(magic, (const unsigned char*)start,
									(const unsigned char*)end);
								if (!val.has_value())
									continue;
								addresses.push_back(val.value());
							}
							uintptr_t val = 0;
							if (addresses.empty()) {
								FUNCTIONS::log("Unable to readjust the relative file offset\n", TYPES::PLG2, 2);
								FUNCTIONS::log("This could be because this was the last file in the EMBB container or it's an error\n", TYPES::PLG2, 2);
							}
							else {
								val = *std::min_element(addresses.begin(), addresses.end());
								file->file_relative_offset = val - file->source_ptr;
								if (file->file_relative_offset >= 4) file->file_relative_offset -= 4;
								FUNCTIONS::log("Readjusted the relative file offset\n", TYPES::PLG2, 2);
							}
							readjustRelOffset = false;
							chunk_changed = false;
							onceNotify = false;
							deleteLoaded();
							FUNCTIONS::log("Finished\n\n", TYPES::PLG2, 1);
						}
					INVALIDCHUNK:;
						invalidChunkCheckOnce = false;
						memcpy(destination, (const void*)(file->source_ptr + (__int64)file->file_relative_offset), size);
					}


					if (!limit) {
						file->file_offset += size;
						file->file_relative_offset += size;
					}


					destination += size;
					bytes_to_read2 -= size;

					if (!bytes_to_read2)
						return 0;

				}
				bytes_to_read = bytes_to_read2;
				goto exit;
			}
			return 0;
		}
	}

	namespace OD {
		inline int __fastcall OODLE_DECOMPRESS_HOOK(uintptr_t in, unsigned int insz, uintptr_t out, unsigned int outsz, int a, int b, int c, void* d, void* e, void* f, void* g, void* h, void* i, int j) {
			using namespace INTERNAL::TYPES::GLOBALS::PLG1;
			using namespace INTERNAL::TYPES::GLOBALS;

			int ret = od_function(in, insz, out, outsz, a, b, c, d, e, f, g, h, i, j);
		reScan:;

			static int datawritten = 1, dump_chunks_counter = 1;
			static bool done = false, once = false, sigonce = false, activeChunk = false, loadOnce = false;
			static uintptr_t dataIndex = 0, index = 0, chunksize = 0;
			uintptr_t offsetIndex = 0;
			uintptr_t address = 0;
			static std::ofstream cacheFileWrite, dump_allFile;
			static std::string debugStr, dump_allStr, currentDebugFile;
			static std::string invalidpath;
			chunks_checked++;

			auto restoreDefault = [&]() {
				invalidpath = one_vec_sigs[index].path;
				activeChunk = false;
				dataIndex = 0;
				datawritten++;
				address = 0;
				std::vector<BYTE>().swap(one_vec_sigs[index].bytes);
				std::vector<BYTE>().swap(exchangedata[index].bytes);
				loadOnce = false;
			};

			if (!once) {
				if (dump_all) {
					dump_allFile.open("plugins\\PacketLoader\\Internal\\dump.dmp");
					dump_allFile.close();
				}
				once = true;
			}

			chunksize = (uintptr_t)outsz;

			if (dump_all) {
				dump_allFile.open("plugins\\PacketLoader\\Internal\\dump.dmp", std::ios::binary | std::ios::app);
				dump_allFile.write((const char*)out, chunksize);
				dump_allFile.close();
			}


			if (cache == read && !activeChunk) {
				std::vector<BYTE> chunk_signature;
				for (int i = 0; i < 1000; ++i)
					chunk_signature.push_back(*(uintptr_t*)(out + i));
				for (const auto& iter : cachesigs) {
					if (iter == chunk_signature)
						goto good;
				}
				return ret;
			}
		good:;

			if (activeChunk) {
				FUNCTIONS::log("Following chunk (h) " + FUNCTIONS::to_hexStr(out) + " - " + FUNCTIONS::to_hexStr(out + outsz) + "\n", TYPES::PLG1, 2);
				if (debug) {
					FUNCTIONS::write_file_binary(currentDebugFile + "\\" + std::to_string(dump_chunks_counter) + ".dmp", (void*)out, chunksize);
					dump_chunks_counter++;
				}
			}

			if (!activeChunk && !one_vec_sigs.empty()) {
				std::vector<std::thread> threads(thwcc - 1);
				auto searchThreadFunc = [&](const std::vector<TYPES::PLG1_::FindData>& sigs) {
					int idx = 0;
					uintptr_t local_address = 0;
					while (local_address == 0 && idx < sigs.size()) {
						if (invalidpath != sigs[idx].path)
							local_address = FUNCTIONS::searchPatternInMemory(sigs[idx], (const unsigned char*)out, (const unsigned char*)(out + chunksize));
						if (local_address != 0) {
							for (int i = 0; i < one_vec_sigs.size(); ++i) {
								if (sigs[idx].signature == one_vec_sigs[i].signature) {
									index = i;
									address = local_address;
								}
							}
						}
						idx++;
					}
				};
				for (int i = 0; i < (int)thwcc - 1; i++) {
					threads[i] = std::thread(searchThreadFunc, std::cref(sigs[i]));
				}
				searchThreadFunc(sigs[sigs.size() - 1]);
				for (auto& thread : threads) {
					thread.join();
				}
				invalidpath = "";
			}
			if (address == 0 && !activeChunk)
				index = 0;
			if (address != 0 && !activeChunk) {

				if (cache == generate) {
					std::vector<BYTE> chunk_signature;
					for (int i = 0; i < 1000; ++i)
						chunk_signature.push_back(*(uintptr_t*)(out + i));

					auto hash = std::hash<std::string>{}(one_vec_sigs[index].path + std::to_string(chunks_checked));

					bool signatureExists = false;
					for (auto& iter : cachesigs) {
						if (iter == chunk_signature) {
							signatureExists = true;
							break;
						}
					}

					if (!signatureExists) {
						cacheFileWrite.open(".\\plugins\\PacketLoader\\Internal\\PLG1\\Signatures\\" + std::to_string(hash) + ".sig", std::ios::binary);
						cacheFileWrite.write((const char*)chunk_signature.data(), chunk_signature.size());
						cacheFileWrite.close();
						cachesigs.insert(chunk_signature);
					}
				}
				FUNCTIONS::log("Found data count (d): " + std::to_string(datawritten) + "\n", TYPES::PLG1, 1);
				FUNCTIONS::log("File: " + one_vec_sigs[index].path + "\n", TYPES::PLG1, 1);
				FUNCTIONS::log("Chunk (h): " + FUNCTIONS::to_hexStr(out) + " - " + FUNCTIONS::to_hexStr(out + outsz) + "\n", TYPES::PLG1, 1);
				FUNCTIONS::log("Found data at (h): " + FUNCTIONS::to_hexStr(address) + "\n", TYPES::PLG1, 1);
				FUNCTIONS::log("Checked chunks (d): " + std::to_string(chunks_checked) + "\n", TYPES::PLG1, 1);
				FUNCTIONS::log("Bytes left in chunk (d): " + std::to_string(chunksize - (address - out)) + "\n", TYPES::PLG1, 1);
				if (debug) {
					dump_chunks_counter = 1;
					FUNCTIONS::log("Debug mode is enabled...\n", TYPES::PLG1, 2);
					FUNCTIONS::log("Dumping the chunks and their respective subsequent ones until fully overwritten or identified as invalid\n", TYPES::PLG1, 2);
					(void)_mkdir(".\\plugins\\PacketLoader\\Internal\\PLG1\\Dumps");
					currentDebugFile = ".\\plugins\\PacketLoader\\Internal\\PLG1\\Dumps\\" + 
						FUNCTIONS::getFileName(one_vec_sigs[index].path) + "_" + std::to_string(one_vec_sigs[index].debug_index);
					(void)_mkdir(currentDebugFile.c_str());
					FUNCTIONS::log("Created a folder: " + currentDebugFile + "\n", TYPES::PLG1, 2);
					FUNCTIONS::write_file_binary(currentDebugFile + "\\" + std::to_string(dump_chunks_counter) + ".dmp", (void*)out, chunksize);
					one_vec_sigs[index].debug_index++;
					dump_chunks_counter++;
					FUNCTIONS::log("Place your breakpoints now and press any key to continue the loading...\n", TYPES::PLG1, 2);
					(void)_getch();
				}
				activeChunk = true;
			}
			if (activeChunk) {
				if (!loadOnce) {
					
					// Load the data from the disc into memory

					if (one_vec_sigs[index].type == INTERNAL::TYPES::PLG1_::Type::Safe) {
						one_vec_sigs[index].bytes = FUNCTIONS::read_block(one_vec_sigs[index].safeProperties.signature_read_offset,
							one_vec_sigs[index].safeProperties.signature_verify_bytes_length, one_vec_sigs[index].path);

						exchangedata[index].bytes = FUNCTIONS::read_block(exchangedata[index].safeProperties.exchange_data_read_offset,
							exchangedata[index].safeProperties.exchange_data_length, exchangedata[index].path);
					}
					else if (one_vec_sigs[index].type == INTERNAL::TYPES::PLG1_::Type::Old) {
						exchangedata[index].bytes = FUNCTIONS::read_block(exchangedata[index].safeProperties.exchange_data_read_offset,
							exchangedata[index].safeProperties.exchange_data_length, exchangedata[index].path);
					}
					else if (one_vec_sigs[index].type == INTERNAL::TYPES::PLG1_::Type::Auto) {
						{
							std::ifstream file(one_vec_sigs[index].path, std::ios::binary | std::ios::ate);
							std::streamsize size = file.tellg();
							file.seekg(0, std::ios::beg);
							std::vector<BYTE> tmp(size);
							file.read((char*)tmp.data(), size);
							one_vec_sigs[index].bytes = tmp;
							
						}
						{
							std::ifstream file(exchangedata[index].path, std::ios::binary | std::ios::ate);
							std::streamsize size = file.tellg();
							file.seekg(0, std::ios::beg);
							std::vector<BYTE> tmp(size);
							file.read((char*)tmp.data(), size);
							exchangedata[index].bytes = tmp;
							
						}
					}
					loadOnce = true;
				}

				if (address == 0) address = out;
				while (offsetIndex < chunksize - (address - out) && dataIndex < exchangedata[index].bytes.size()) {
					if (one_vec_sigs[index].type != INTERNAL::TYPES::PLG1_::Type::Old)
						if (index < one_vec_sigs[index].bytes.size())
							if (*(BYTE*)(address + offsetIndex) != one_vec_sigs[index].bytes[dataIndex]) {
								FUNCTIONS::log("Invalid chunk detected after (d): " + std::to_string(offsetIndex) + " bytes\n", TYPES::PLG1, 3);
								FUNCTIONS::log("Rescanning the chunk for other data...\n", TYPES::PLG1, 3);
								if (debug)
									FUNCTIONS::log("Use the last dump file carefully\n", TYPES::PLG1, 4);
								std::cout << "\n";
								restoreDefault();
								goto reScan;
							}
					if (one_vec_sigs[index].remove) {
						FUNCTIONS::log("Remove mode is turned on...\n", TYPES::PLG1, 2);
						FUNCTIONS::log("Removed the magic and version from the file!\n", TYPES::PLG1, 2);
						FUNCTIONS::log("Rescanning the chunk for other data...\n\n", TYPES::PLG1, 2);
						*(__int64*)(address + offsetIndex) = 0i64;
						restoreDefault();
						goto reScan;
					}
					else 
						*(BYTE*)(address + offsetIndex) = exchangedata[index].bytes[dataIndex];
					dataIndex++;
					offsetIndex++;
				}
				if (dataIndex >= exchangedata[index].bytes.size()) {
					FUNCTIONS::log("Completely overwritten\n", TYPES::PLG1, 1);
					FUNCTIONS::log("Rescanning the chunk for other data...\n\n", TYPES::PLG1, 1);
					restoreDefault();
					chunks_checked--;
					goto reScan;
				}
			}
			return ret;
		}

	}
}