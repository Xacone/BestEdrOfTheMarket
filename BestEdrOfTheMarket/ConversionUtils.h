#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <string>


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