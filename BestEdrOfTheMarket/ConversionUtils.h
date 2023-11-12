#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <algorithm>


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
    // Convertir le tableau WCHAR en char*
    char* charArray = new char[250];  // Assumer que chaque caractère WCHAR se traduit en un caractère char.

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