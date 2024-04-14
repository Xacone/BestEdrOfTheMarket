/**
 * @file ConversionUtils.h
 * @brief Utility functions for conversion between different data types & output formatting.
 * 
 */


#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <algorithm>


/**
	* Converts an LPVOID to a BYTE array.
    * @param lpVoid The LPVOID to convert.
    * @return The BYTE array.
*/

BYTE* LPVOIDToBYTE(LPVOID lpVoid) {
    return reinterpret_cast<BYTE*>(lpVoid);
}


/**
    * converts a hex string to an LPCVOID.
    * @param hexString The hex string to convert.
    * @return The LPCVOID.
*/
LPCVOID hexStringToLPCVOID(const std::string& hexString) {

    std::string hexStringWithoutSpaces;
    for (char c : hexString) {
        if (c != ' ')
            hexStringWithoutSpaces += c;
    }

    unsigned long long intPtr;
    std::stringstream ss;
    ss << std::hex << hexStringWithoutSpaces;
    ss >> intPtr;

    LPCVOID lpVoid = reinterpret_cast<LPCVOID>(intPtr);

    return lpVoid;
}


/**
    * Convert a byte array to a hex string.
	* @param bytes The byte array to convert.
	* @param size The size of the byte array.
	* @return The hex string.
*/
std::string bytesToHexString(const BYTE* bytes, size_t size) {

	std::stringstream ss;
	ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < size; ++i) {
		ss << std::setw(2) << static_cast<int>(bytes[i]);
	}
	return ss.str();
}


/**
    * Removes the BOM (Byte Order Mark) from the given string.
    * @param input The input string.
    * @return The string without the BOM.
*/
std::string removeBOM(const std::string& input) {

    if (input.size() >= 3 && input[0] == '\xEF' && input[1] == '\xBB' && input[2] == '\xBF') {
        return input.substr(3);
    }
    else {
        return input;
    }
}


/**

	* Convert a CHAR representing a hex character to its BYTE equivalent.

 *  @param byteArray The byte array to convert.

 *  @param size The size of the byte array.

 *  @return The hex string.

 */
BYTE hexToByte(char hex) {
    if (hex >= '0' && hex <= '9')
        return hex - '0';
    else if (hex >= 'A' && hex <= 'F')
        return hex - 'A' + 10;
    else if (hex >= 'a' && hex <= 'f')
        return hex - 'a' + 10;
    else
        return 0;
}


/**
    * Convert a hex string to a byte array.

 *  @param hexString The hex string to convert.

 *  @param length The length of the resulting byte array.

 *  @return The byte array.

 */


BYTE* convertHexToBytes(const char* hexString, size_t& length) {
    length = strlen(hexString) / 2;
    BYTE* bytes = new BYTE[length];

    for (size_t i = 0; i < length; ++i) {
        bytes[i] = (hexToByte(hexString[i * 2]) << 4) | hexToByte(hexString[i * 2 + 1]);
    }

    return bytes;
}


/**
    * Convert a char array to a LPWSTR.
	* @param charArray The char array to convert.
	* @return The LPWSTR.
*/

LPWSTR ConvertCharToLPWSTR(const char* charArray)
{
	int length = strlen(charArray) + 1;
	LPWSTR str = new WCHAR[length];
	MultiByteToWideChar(CP_ACP, 0, charArray, length, str, length);
	return str;
}

/**
    * Convert a char array to a LPCWSTR.
	* @param charArray The char array to convert.
	* @return The LPCWSTR.
*/

LPCWSTR ConvertCharToLPCWSTR(const char* charArray)
{
    int length = strlen(charArray) + 1;
    int lengthW = MultiByteToWideChar(CP_ACP, 0, charArray, length, NULL, 0);
    wchar_t* wideArray = new wchar_t[lengthW];
    MultiByteToWideChar(CP_ACP, 0, charArray, length, wideArray, lengthW);
    return wideArray;
}

/**
    * Convert a wide string to a char array.
 * @param wstr The wide string to convert.
 * @return The char array.

*/

const char* WCharToConstChar(const WCHAR* wstr)
{
    std::string str;
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
    if (len > 0)
    {
        str.resize(len);
        WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &str[0], len, NULL, NULL);
    }
    return str.c_str();
}

/**
    * Convert a wide string to a char array.
    * @param wideArray The wide string to convert.
    * @return The char array.
	*/

char* WideStringToChar(const WCHAR wideArray[250]) {

    char* charArray = new char[250];  

    for (int i = 0; i < 250; i++) {
        int charCount = WideCharToMultiByte(CP_UTF8, 0, &wideArray[i], 1, &charArray[i], 1, NULL, NULL);
    }

    return charArray;
}

/**
* 
* Convert a byte array to a hex string.
* @param byteArray The byte array to convert.
* @param size The size of the byte array.
* @return The hex string.
*/

std::vector<BYTE> hexStringToBytesVector(const std::string& hexString) {

    std::vector<BYTE> bytes;

    for (size_t i = 0; i < hexString.length(); i += 2) {
        std::string byteString = hexString.substr(i, 2);
        BYTE byte = static_cast<BYTE>(std::stoi(byteString, nullptr, 16));
        bytes.push_back(byte);
    }

    return bytes;
}

/**

 * Convert a hex string to a byte array.

 *  @param hexString The hex string to convert.

 *  @param length The length of the resulting byte array.

 *  @return The byte array.

 */

BYTE* hexStringToByteArray(const std::string& hexString, size_t& length) {

    length = std::count_if(hexString.begin(), hexString.end(), [](char c) { return !std::isspace(c); }) / 2;

    BYTE* byteArray = new BYTE[length];

    std::stringstream ss(hexString);
    for (size_t i = 0; i < length; ++i) {
        int byteValue;
        ss >> std::hex >> byteValue; 
        byteArray[i] = static_cast<BYTE>(byteValue);
    }

    return byteArray;
}

/**
    * Print a byte array.
 
 *  @param byteArray The byte array to print.
 
 *  @param size The size of the byte array.
 */


void printByteArray(const BYTE* byteArray, size_t size) {

    for (size_t i = 0; i < size; ++i) {
        std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)(byteArray[i]) << " ";
    }
    std::cout << std::dec << std::endl;
}

/**
 * Print a byte array without zeros and breaks.
 
 *  @param byteArray The byte array to print.
 
 *  @param size The size of the byte array.
 */

void printByteArrayWithoutZerosAndBreaks(const BYTE* byteArray, size_t size) {

    for (size_t i = 0; i < size; ++i) {
        if (byteArray[i] != 0x00 && byteArray[i] != 0xcc) {
            std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)(byteArray[i]) << " ";
        }
    }      
    std::cout << std::dec << std::endl;
}

/**
* 
* Convert a char array to a byte array.
* 
* @param input The char array to convert.
*/

BYTE* charToByte(const char* input) {

    size_t length = strlen(input);
    BYTE* result = new BYTE[length];
    for (size_t i = 0; i < length; ++i) {
        result[i] = static_cast<BYTE>(input[i]);
    }

    return result;

}

/**
 * Convert a char array to a hex dump.
 
 *  @param input The char array to convert.
 
 *  @return The hex dump.
 */

BYTE* charToHexDump(const char* input) {

    size_t len = strlen(input);
    size_t hexDumpSize = len * 2;
    BYTE* hexDump = new BYTE[hexDumpSize + 1];
    hexDump[hexDumpSize] = '\0';
    return hexDump;

}

/**
    * Convert a hex string to a byte array.
 
 *  @param hexString The hex string to convert.
 
 *  @param size The size of the resulting byte array.
 
 *  @return The byte array.
 */


BYTE* hexStringToBytes(const std::string& hexString, size_t& size) {
    size_t length = hexString.length();
    if (length % 2 != 0) {
        std::cerr << "[!] Hex string length must be even." << std::endl;
        return nullptr;
    }

    size = length / 2;
    BYTE* byteArray = new BYTE[size];

    for (size_t i = 0; i < length; i += 2) {
        std::string byteString = hexString.substr(i, 2);
        byteArray[i / 2] = static_cast<BYTE>(std::stoi(byteString, nullptr, 16));
    }

    return byteArray;
}

/**

 * Reverse the order of bytes in the given buffer.

 *  @param bytes The buffer to reverse.

 *  @param size The size of the buffer.

 */

void reverseBytesOrder(BYTE* bytes, size_t size) {
    // Implement the logic to reverse the order of bytes
    for (size_t i = 0; i < size / 2; ++i) {
        std::swap(bytes[i], bytes[size - i - 1]);
    }
}

/**
 * Print a hex dump of the given buffer.
 
 *  @param buffer The buffer to print.
 */


void printAsciiDump(const uint8_t* buffer, size_t size) {
    const int width = 16; // Number of bytes per line
    std::cout << std::hex << std::setfill('0');

    for (size_t i = 0; i < size; i += width) {
        std::cout << "0x" << std::setw(8) << i << ": ";

        for (size_t j = 0; j < width; ++j) {
            if (i + j < size) {
                std::cout << std::setw(2) << static_cast<int>(buffer[i + j]) << " ";
            }
            else {
                std::cout << "   "; // Extra spaces for alignment
            }
        }

        std::cout << " ";
        for (size_t j = 0; j < width && i + j < size; ++j) {
            char c = buffer[i + j];
            if (c >= 32 && c <= 126) {
                std::cout << c;
            }
            else {
                std::cout << "."; // Non-printable characters shown as '.'
            }
        }

        std::cout << std::endl;
    }
}

/**
 * Print a hex dump of the given buffer.
 
 *  @param buffer The buffer to print.
 */

void printAsciiDumpWithoutZeros(const BYTE* byteArray, size_t size, size_t bytesPerLine = 16) {
    
    for (size_t i = 0; i < size; i += bytesPerLine) {
        for (size_t j = 0; j < bytesPerLine; ++j) {
            size_t index = i + j;
            if (byteArray[index] != 0x00) {
                 if (index < size) {
                    std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)(byteArray[index]) << " ";
                }
            }
            else {
                std::cout << "   "; // Padding for incomplete lines
            }
        }

        // Print ASCII representation
        std::cout << "   ";
        for (size_t j = 0; j < bytesPerLine; ++j) {
            size_t index = i + j;
            if (byteArray[index] != 0x00) {
                if (index < size) {
                        char c = (byteArray[index] >= 32 && byteArray[index] <= 126) ? byteArray[index] : '.';
                        std::cout << c;
                    }
                } else {
                    std::cout << " ";
                }
        }

        std::cout << std::endl;
    }
}

/**
 * Print a null-terminated hex dump of the given buffer.
 
 *  @param buffer The buffer to print.
 */

void printNullTerminatedHexDump(const uint8_t* buffer) {
    const int width = 16; // Number of bytes per line
    std::cout << std::hex << std::setfill('0');

    size_t i = 0;

    std::cout << "0x" << std::setw(8) << i << ": ";

    while (buffer[i] != '\0') {
        std::cout << std::setw(2) << static_cast<int>(buffer[i]) << " ";

        if (++i % width == 0) {
            std::cout << std::endl;
            std::cout << "0x" << std::setw(8) << i << ": ";
        }
    }

    std::cout << std::endl;
}

/**
 * Print a null-terminated ASCII dump of the given buffer.
 
 *  @param buffer The buffer to print.
 */

std::string getCurrentDateTime() {

    auto now = std::chrono::system_clock::now();
    std::time_t currentTime = std::chrono::system_clock::to_time_t(now);
    std::tm* timeInfo = std::localtime(&currentTime);
    std::ostringstream oss;
    oss << std::put_time(timeInfo, "%Y-%m-%d %H:%M:%S");
    return oss.str();

}
