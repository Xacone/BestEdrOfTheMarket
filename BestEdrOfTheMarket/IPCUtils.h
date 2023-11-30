#pragma once

#include <Windows.h>
#include <tchar.h>
#include <strsafe.h>
#include <iostream>

using namespace std;

#define PIPE_BUFFER_SIZE 512

void killThatProcess(HANDLE hProc, HANDLE hPipe) {
	CloseHandle(hPipe);
	TerminateProcess(hProc, -1);
}

HANDLE initPipe(LPCWSTR pipeName) {

	HANDLE hPipe;

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

	if (hPipe == INVALID_HANDLE_VALUE || hPipe == NULL) {
		cout << "Error when initializing BEOTM pipe." << endl;
		exit(-25);
	}

	return hPipe;
}

int waitForReponseOnPipe(HANDLE hPipe, TCHAR* buffer, DWORD* pdwBytesRead) {
	while (true) {
		if (ConnectNamedPipe(hPipe, NULL)) {

			while (ReadFile(hPipe, buffer, sizeof(buffer), pdwBytesRead, NULL) != 0) {

				LPCWSTR response = L"Et c'est des snitchhhhh !!";
				WriteFile(hPipe, response, sizeof(response), pdwBytesRead, NULL);
			}

			DisconnectNamedPipe(hPipe);
		}
	}

	return 0;
}