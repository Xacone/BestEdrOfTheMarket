#pragma once

#include <Windows.h>

bool containsSequence(const BYTE* haystack, size_t haystackSize, const BYTE* needle, size_t needleSize) {
	for (size_t i = 0; i <= haystackSize - needleSize; ++i) {
		if (memcmp(haystack + i, needle, needleSize) == 0) {
			return true;
		}
	}
	return false;
}