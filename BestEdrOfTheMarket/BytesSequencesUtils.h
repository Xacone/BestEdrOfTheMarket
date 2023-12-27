#pragma once

#include <Windows.h>

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

bool searchForOccurenceInByteArray(BYTE* tab, int tailleTab, BYTE* chaineHex, int tailleChaineHex) {
	for (int i = 0; i <= tailleTab - tailleChaineHex; i++) {
		bool correspondance = true;
		for (int j = 0; j < tailleChaineHex; j++) {
			if (tab[i + j] != chaineHex[j]) {
				correspondance = false;
				break;
			}
		}
		if (correspondance) {
			return true;
		}
	}
	return false;
}

