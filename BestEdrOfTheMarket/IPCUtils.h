#pragma once

#include <Windows.h>
#include <tchar.h>
#include <strsafe.h>
#include <iostream>
#include "ErrorsReportingUtils.h"
#include "ColorsUtils.h"
#include "BytesSequencesUtils.h"
#include <vector>
#include <json/json.h> 

#define PIPE_BUFFER_SIZE 512

typedef void (*DeleteMonitoringWorkerThreads)();
typedef void (*Startup)();

class IpcUtils {

private: 

	//static std::vector<HANDLE> pipes;

	HANDLE hPipe;
	HANDLE targetProcess;
	BYTE buffer[1024];
	DWORD bytesRead;
	LPCWSTR pipeName;
	BOOL _v_;
	std::unordered_map<BYTE*, SIZE_T> &dllPatterns;
	std::unordered_map<BYTE*, SIZE_T> &generalPatterns;

	DeleteMonitoringWorkerThreads deleteMonitoringFunc;
	Startup startupFunc;

public:

	IpcUtils(LPCWSTR pipeName,
		HANDLE& tProcess,
		BOOL& verbose,
		std::unordered_map<BYTE*, SIZE_T>& dllPatterns,
		std::unordered_map<BYTE*, SIZE_T>& generalPatterns,
		DeleteMonitoringWorkerThreads f1,
		Startup f2) :

		pipeName(pipeName),
		targetProcess(tProcess),
		_v_(verbose),
		dllPatterns(dllPatterns),
		generalPatterns(generalPatterns),
		deleteMonitoringFunc(f1),
		startupFunc(f2)

	{}

	void alertAndKillThatProcess(HANDLE hProc) {
		CloseHandle(hPipe);
		MessageBoxA(NULL, "Malicious process detected (DLL) ! Terminating it...", "BestEdrOfTheMarket", MB_ICONEXCLAMATION);
		printRedAlert("Malicious process detected! Terminating it...");
		TerminateProcess(hProc, -1);
	}

	HANDLE initPipeAndWaitForConnection() {

		HANDLE hPipe;
		char buffer[4096];
		DWORD bytesRead;

		while (true) {

			hPipe = CreateNamedPipe(
				pipeName,
				PIPE_ACCESS_DUPLEX,
				PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
				PIPE_UNLIMITED_INSTANCES,
				PIPE_BUFFER_SIZE,
				PIPE_BUFFER_SIZE,
				0,
				NULL
			);

			//pipes.push_back(hPipe);

			if (hPipe == INVALID_HANDLE_VALUE || hPipe == NULL) {
				std::cerr << "Error when initializing BEOTM pipe." << std::endl;
				printLastError();
				exit(-25);
			}

			if (ConnectNamedPipe(hPipe, nullptr)) {
				if (ReadFile(hPipe, buffer, sizeof(buffer), &bytesRead, nullptr)) {

					std::string jsonString((char*)(buffer), bytesRead);

					Json::Value root;
					Json::CharReaderBuilder reader;
					std::istringstream jsonStream(jsonString);

					if (Json::parseFromStream(reader, jsonStream, &root, nullptr)) {
						std::string routineName = root["Function"].asString();
						
						printBlueAlert("Intercepted " + routineName);	

						size_t capturedDataSize = (size_t)strlen(root["Data"].asCString());
						BYTE* hexDump = hexStringToBytes(root["Data"].asCString(), capturedDataSize);


						///TODO : debug
						std::string jsonDump((char*)buffer);
						std::cout << jsonDump << "\n" << std::endl;
						

						for (const auto& pair : dllPatterns) {
							if (containsSequence(hexDump, bytesRead, pair.first, pair.second)) {
								alertAndKillThatProcess(targetProcess);
									deleteMonitoringFunc();
									startupFunc();
							}
						}

						for (const auto& pair : generalPatterns) {
							if (containsSequence(hexDump, bytesRead, pair.first, pair.second)) {
								alertAndKillThatProcess(targetProcess);
								deleteMonitoringFunc();
								startupFunc();
							}
						}

					}


				}

			
 
			}
		}

		return hPipe;
	}
	
	void terminatePipeConnection() {
		if (!DisconnectNamedPipe(hPipe)) {
			std::cerr << "Error when disconnecting from BEOTM pipe." << std::endl;
			CloseHandle(hPipe);
			exit(-28);
		}
	}
};






