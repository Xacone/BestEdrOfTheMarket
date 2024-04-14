/**
 * @file BytesSequencesUtils.h
 * @brief Utilities for checks on bytes sequences
*/


#pragma once

#include <Windows.h>

/**
* 
* Function that searches for a sequence in a byte array
* 
* @param haystack : sequence to search in (haystack)
* @param haystackSize : size of the haystack
* @param needle : sequence to search
* @param needleSize : size of the needle
**/

bool containsSequence(const BYTE* haystack, size_t haystackSize, const BYTE* needle, size_t needleSize) {
    if (haystack == nullptr || needle == nullptr) {
        return false;
    }

    if (needleSize > haystackSize) {
        return false;
    }

    for (size_t i = 0; i <= haystackSize - needleSize; ++i) {
        if (memcmp(haystack + i, needle, needleSize-1) == 0) {
            return true;
        }
    }
    return false;
}
