#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <algorithm>

BYTE* LPVOIDToBYTE(LPVOID lpVoid) {
    return reinterpret_cast<BYTE*>(lpVoid);
}

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

std::string bytesToHexString(const BYTE* bytes, size_t size) {

	std::stringstream ss;
	ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < size; ++i) {
		ss << std::setw(2) << static_cast<int>(bytes[i]);
	}
	return ss.str();
}

std::string removeBOM(const std::string& input) {

    if (input.size() >= 3 && input[0] == '\xEF' && input[1] == '\xBB' && input[2] == '\xBF') {
        return input.substr(3);
    }
    else {
        return input;
    }
}
    
LPCWSTR ConvertCharToLPCWSTR(const char* charArray)
{
    int length = strlen(charArray) + 1;
    int lengthW = MultiByteToWideChar(CP_ACP, 0, charArray, length, NULL, 0);
    wchar_t* wideArray = new wchar_t[lengthW];
    MultiByteToWideChar(CP_ACP, 0, charArray, length, wideArray, lengthW);
    return wideArray;
}

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

char* WideStringToChar(const WCHAR wideArray[250]) {

    char* charArray = new char[250];  

    for (int i = 0; i < 250; i++) {
        int charCount = WideCharToMultiByte(CP_UTF8, 0, &wideArray[i], 1, &charArray[i], 1, NULL, NULL);
    }

    return charArray;
}

std::vector<BYTE> hexStringToBytesVector(const std::string& hexString) {

    std::vector<BYTE> bytes;

    for (size_t i = 0; i < hexString.length(); i += 2) {
        std::string byteString = hexString.substr(i, 2);
        BYTE byte = static_cast<BYTE>(std::stoi(byteString, nullptr, 16));
        bytes.push_back(byte);
    }

    return bytes;
}

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

void printByteArray(const BYTE* byteArray, size_t size) {

    for (size_t i = 0; i < size; ++i) {
        std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)(byteArray[i]) << " ";
    }
    std::cout << std::dec << std::endl;
}

void printByteArrayWithoutZerosAndBreaks(const BYTE* byteArray, size_t size) {

    for (size_t i = 0; i < size; ++i) {
        if (byteArray[i] != 0x00 && byteArray[i] != 0xcc) {
            std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)(byteArray[i]) << " ";
        }
    }      
    std::cout << std::dec << std::endl;
}

BYTE* charToByte(const char* input) {

    size_t length = strlen(input);
    BYTE* result = new BYTE[length];
    for (size_t i = 0; i < length; ++i) {
        result[i] = static_cast<BYTE>(input[i]);
    }

    return result;

}

BYTE* charToHexDump(const char* input) {

    size_t len = strlen(input);
    size_t hexDumpSize = len * 2;
    BYTE* hexDump = new BYTE[hexDumpSize + 1];
    hexDump[hexDumpSize] = '\0';
    return hexDump;

}


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


void reverseBytesOrder(BYTE* bytes, size_t size) {
    // Implement the logic to reverse the order of bytes
    for (size_t i = 0; i < size / 2; ++i) {
        std::swap(bytes[i], bytes[size - i - 1]);
    }
}

//void printAsciiDumpWithoutZeros(const BYTE* byteArray, size_t size, size_t bytesPerLine = 16) {
//    
//    for (size_t i = 0; i < size; i += bytesPerLine) {
//        for (size_t j = 0; j < bytesPerLine; ++j) {
//            size_t index = i + j;
//            if (byteArray[index] != 0x00) {
//                 if (index < size) {
//                    std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)(byteArray[index]) << " ";
//                }
//            }
//            else {
//                std::cout << "   "; // Padding for incomplete lines
//            }
//        }
//
//        // Print ASCII representation
//        std::cout << "   ";
//        for (size_t j = 0; j < bytesPerLine; ++j) {
//            size_t index = i + j;
//            if (byteArray[index] != 0x00) {
//                if (index < size) {
//                        char c = (byteArray[index] >= 32 && byteArray[index] <= 126) ? byteArray[index] : '.';
//                        std::cout << c;
//                    }
//                } else {
//                    std::cout << " ";
//                }
//        }
//
//        std::cout << std::endl;
//    }
//}


std::string getCurrentDateTime() {

    auto now = std::chrono::system_clock::now();
    std::time_t currentTime = std::chrono::system_clock::to_time_t(now);
    std::tm* timeInfo = std::localtime(&currentTime);
    std::ostringstream oss;
    oss << std::put_time(timeInfo, "%Y-%m-%d %H:%M:%S");
    return oss.str();

}
