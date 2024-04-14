/**
 * @file ErrorsReportingUtils.h
 * @brief Error reporting utilities.
 *
 * Description détaillée du fichier C++.
 */

#pragma once

#include <Windows.h>
#include <iostream>

/**
	* Retrieves and prints the last error message (explicitly).
*/
void printLastError() {
	DWORD errorCode = GetLastError();

	if (errorCode != 0) {
		LPVOID errorMessage;
		DWORD result = FormatMessage(
			FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
			NULL,
			errorCode,
			0, // Default language
			(LPWSTR)&errorMessage,
			0,
			NULL
		);

		if (result != 0) {
			wprintf(L"Error Code: %lu\n", errorCode);
			wprintf(L"Error Message: %s\n", (LPWSTR)errorMessage);

			LocalFree(errorMessage);
		}
		else {
			std::cerr << "Failed to retrieve error message." << std::endl;
		}
	}
	else {
		std::cout << "No error." << std::endl;
	}
}
