#pragma once

#include <Windows.h>
#include <Psapi.h>
#include <iostream>
#include <sstream>

#define BEOTM_VERSION "1.1.0"

std::string GetProcessPathByPID(DWORD pid, HANDLE& hProc) {
    char processPath[MAX_PATH];
    if (GetModuleFileNameExA(hProc, NULL, processPath, MAX_PATH) == 0) {
        return "";
    }
    return processPath;
}

std::string dllHookingReportingJson(
    DWORD pid,
    const std::string& processName,
    const std::string& defenseMechanism,
    const std::string& address,
    const std::string& detectedPattern,
    const std::string& patternList,
    const std::string& foundIn
    ) {

    std::stringstream json;

    json << "{\n"
        << "  \"Version\" : \"" << BEOTM_VERSION << "\",\n"
        << "  \"MaliciousPID\" : \"" << std::to_string(pid) << "\",\n"
        << "  \"MalicousProcessPath\" : \"" << processName << "\",\n"
        << "  \"DefenseMechanism\" : \"" << defenseMechanism << "\",\n"
        << "  \"DateTime\" : \"" << std::string(__DATE__) + " " + std::string(__TIME__) << "\",\n"
        << "  \"Address\" : \"" << address << "\",\n"
        << "  \"DetectedPattern\" : \"" << detectedPattern << "\",\n"
        << "  \"PatternList\" : \"" << patternList << "\",\n"
        << "  \"FoundIn\" : \"" << foundIn << "\"\n"
        << "}";

    return json.str();
}

std::string directSyscallReportingJson(
    DWORD pid, 
    const std::string& processName,
    const std::string& defenseMechanism,
    const std::string& address
    ) {

    std::stringstream json;

    json << "{\n"
        << "  \"Version\" : \"" << BEOTM_VERSION << "\",\n"
        << "  \"MaliciousPID\" : \"" << std::to_string(pid) << "\",\n"
        << "  \"MaliciousProcessPath\" : \"" << processName << "\",\n"
        << "  \"DefenseMechanism\" : \"" << defenseMechanism << "\",\n"
        << "  \"DateTime\" : \"" << std::string(__DATE__) + " " + std::string(__TIME__) << "\",\n"
        << "  \"StubAddress\" : \"" << address << "\",\n"
        << "}";

    return json.str();
}

std::string stackFrameReportingJson(
    DWORD pid,
    const std::string& processName,
    const std::string& defenseMechanism,
    const std::string& functionName,
    const DWORD_PTR& FrameAddress,
    const std::string& patternList,
    const std::string& foundIn
) {

    std::stringstream json;

    json << "{\n"
		<< "  \"Version\" : \"" << BEOTM_VERSION << "\",\n"
		<< "  \"MaliciousPID\" : \"" << std::to_string(pid) << "\",\n"
		<< "  \"MaliciousProcessPath\" : \"" << processName << "\",\n"
		<< "  \"DefenseMechanism\" : \"" << defenseMechanism << "\",\n"
		<< "  \"DateTime\" : \"" << std::string(__DATE__) + " " + std::string(__TIME__) << "\",\n"
		<< "  \"Function :\"" << functionName << "\",\n"
        << "  \"Stack Frame Offset : \" : \"" << std::hex << FrameAddress << "\",\n"
		<< "  \"PatternList\" : \"" << patternList << "\",\n"
        << "  \"FoundIn\" : \"" << foundIn << "\"\n" <<
"}";

    return json.str();
}

std::string yaraRulesReportingJson(
    DWORD pid,
    const std::string& processName,
    const std::string& defenseMechanism,
    const std::string& yaraRuleName,
    const std::string& yaraRuleNamespace
) {
std::stringstream json;

	json << "{\n"
		<< "  \"Version\" : \"" << BEOTM_VERSION << "\",\n"
		<< "  \"MaliciousPID\" : \"" << std::to_string(pid) << "\",\n"
		<< "  \"MaliciousProcessPath\" : \"" << processName << "\",\n"
		<< "  \"DefenseMechanism\" : \"" << defenseMechanism << "\",\n"
		<< "  \"DateTime\" : \"" << std::string(__DATE__) + " " + std::string(__TIME__) << "\",\n"
		<< "  \"YaraRuleName :\"" << yaraRuleName << "\",\n"
		<< "  \"YaraRuleNamespace : \" : \"" << yaraRuleNamespace << "\",\n"
		<< "}";

    return json.str();
}