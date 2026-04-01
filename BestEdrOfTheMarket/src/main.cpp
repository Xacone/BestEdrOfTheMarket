#include "Utils.h"

#pragma comment(lib, "ftxui-component.lib")
#pragma comment(lib, "ftxui-dom.lib")
#pragma comment(lib, "ftxui-screen.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libyara.lib")

using namespace ftxui;
using namespace std;

#define BEOTM_RETRIEVE_DATA_BUFFER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define BEOTM_RETRIEVE_DATA_FILE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define BEOTM_RETRIEVE_DATA_BYTE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define END_THAT_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x216, METHOD_BUFFERED, FILE_ANY_ACCESS)

UINT32 curPid;

YR_COMPILER* compiler;
YR_RULES* rules;
YR_SCANNER* scanner = nullptr;
int yara_rules_count = 0;

std::queue<char*> g_bytesEvents;
std::queue<char*> g_fileEvents;

HANDLE hBeotmDevice;

std::mutex security_event_mutex;
std::atomic<bool> should_update(false);

std::vector<std::string> tab_values{
    "Detection Events (0) | Score: 100 (SECURE)",
    "About"
};
int tab_selected = 0;
auto tab_toggle = Toggle(&tab_values, &tab_selected);

std::vector<std::string> tab_1_menu_items{
};

auto screen = ScreenInteractive::Fullscreen();

int tab_1_selected = 0;
auto tab_1_menu = Menu(&tab_1_menu_items, &tab_1_selected);

std::unordered_set<std::string> benignFSPaths;
std::unordered_set<std::string> loadedYaraRulePaths;
std::unordered_set<std::string> lolDriverNames;
std::unordered_set<std::string> detectedLolDriverPaths;

const std::string kLoadedPotatoYaraRulesDir = R"(D:\Loaded-Potato\detections\yara)";
const std::string kLoadedPotatoLolDriversCachePath = R"(D:\Loaded-Potato\detections\loldrivers\loldrivers_cache.json)";
const std::string kLoadedPotatoSigmaRulesDir = R"(D:\Loaded-Potato\detections\sigma)";
const std::string kDefaultEventsLogPath = R"(beotm_events.jsonl)";

enum class DetectionSeverity : int {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
};

struct CorrelationEvent {
    time_t timestamp;
    std::string method;
    DetectionSeverity severity;
};

struct SigmaLiteSelector {
    std::vector<std::string> containsAny;
    std::vector<std::string> containsAll;
    std::vector<std::string> startsWithAny;
    std::vector<std::string> endsWithAny;
};

struct SigmaLiteRule {
    std::string title;
    std::string level;
    std::string condition;
    std::unordered_map<std::string, SigmaLiteSelector> selectors;
};

std::unordered_map<UINT32, std::deque<CorrelationEvent>> g_recentEventsByPid;
std::unordered_map<UINT32, time_t> g_lastCorrelationAlertByPid;
std::array<int, 5> g_severityCounters = { 0, 0, 0, 0, 0 };
std::vector<SigmaLiteRule> g_sigmaRules;
std::unordered_set<std::string> g_sigmaMatchDedup;
std::mutex events_log_mutex;

std::string startupAsciiTitle = R"(

                          .           .   .        .           .          /         :  .
                    . .        .  .      /.   .      .    .     .     .  / .      . ' .
                        .  +       .    /     .          .          .   /      .
                       .            .  /         .            .        *   .         .     .
                      .   .      .    *     .     .    .      .   .       .  .
                          .           .           .           .           .         +  .
                  . .        .  .       .   .  ,-._  .    .     .     .    .      .   .
                                              /   |)
                 .   +      .          ___/\_'--._|"...__/\__.._._/~\        .         .   .
                       .          _.--'      o/o "@                  `--./\          .   .
                           /~~\/~\           '`  /(___                     `-/~\_            .
                 .      .-'                 /`--'_/   \                          `-/\_
                  _/\.-'                   /\        , \                           __/~\/\-.__
                  ____            _     _____ ____  ____     ___   __   _____ _
                 | __ )  ___  ___| |_  | ____|  _ \|  _ \   / _ \ / _| |_   _| |__   ___
                 |  _ \ / _ \/ __| __| |  _| | | | | |_) | | | | | |     | | | '_ \ / _ \
                 | |_) |  __/\__ \ |_  | |___| |_| |  _ <  | |_| |  _|   | | | | | |  __/
                 |____/_\___||___/\__| |_____|____/|_| \_\  \___/|_|     |_| |_| |_|\___|   
                 |  \/  | __ _ _ __| | _____| |_                                         
                 | |\/| |/ _` | '__| |/ / _ \ __|                                        
                 | |  | | (_| | |  |   <  __/ |_                                    
                 |_|  |_|\__,_|_|  |_|\_\___|\__|                                                               


                                                Version 3              
        
                             https://github.com/Xacone/BestEdrOfTheMarket/
   
                                     @Yazidou - github.com/Xacone 



                               "A ses yeux, j'serai toujours le plus fort,
                                         ce sont des faibles"
)";

std::vector<std::string> detectEventsDetails;

std::vector<std::string> SplitLines(const std::string& str) {
    std::stringstream ss(str);
    std::string line;
    std::vector<std::string> lines;
    while (std::getline(ss, line)) {
        lines.push_back(line);
    }
    return lines;
}

std::wstring GetFullPath(const std::wstring& relativePath) {
    WCHAR fullPath[MAX_PATH];

    DWORD result = GetFullPathNameW(relativePath.c_str(), MAX_PATH, fullPath, nullptr);
    if (result == 0) {
        std::wcerr << L"Failed to get full path. Error: " << GetLastError() << std::endl;
        return L"";
    }

    return std::wstring(fullPath);
}

std::string QueryDosDevicePath(const std::string& devicePath) {
    char driveLetter = 'A';
    char deviceName[256];
    char targetPath[1024];
    DWORD result;

    for (driveLetter = 'A'; driveLetter <= 'Z'; ++driveLetter) {
        std::string drive = std::string(1, driveLetter) + ":";
        result = QueryDosDeviceA(drive.c_str(), deviceName, 256);
        if (result != 0) {
            if (devicePath.find(deviceName) == 0) {
                std::string fullPath = drive + devicePath.substr(strlen(deviceName));
                return fullPath;
            }
        }
    }
    return "";
}

std::string ToLowerCopy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
        });

    return value;
}

std::string BuildTimestamp() {
    time_t now = time(0);
    struct tm timeinfo;
    localtime_s(&timeinfo, &now);
    char date_time[80];
    strftime(date_time, sizeof(date_time), "%Y-%m-%d %H:%M:%S", &timeinfo);
    return std::string(date_time);
}

std::string TrimCopy(const std::string& input) {
    size_t start = input.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) {
        return "";
    }

    size_t end = input.find_last_not_of(" \t\r\n");
    return input.substr(start, end - start + 1);
}

std::string StripOuterQuotes(const std::string& input) {
    if (input.size() >= 2) {
        if ((input.front() == '"' && input.back() == '"') ||
            (input.front() == '\'' && input.back() == '\'')) {
            return input.substr(1, input.size() - 2);
        }
    }

    return input;
}

std::string RemoveYamlInlineComment(const std::string& input) {
    bool inSingleQuote = false;
    bool inDoubleQuote = false;

    for (size_t i = 0; i < input.size(); ++i) {
        char c = input[i];
        if (c == '\'' && !inDoubleQuote) {
            inSingleQuote = !inSingleQuote;
        }
        else if (c == '"' && !inSingleQuote) {
            inDoubleQuote = !inDoubleQuote;
        }
        else if (c == '#' && !inSingleQuote && !inDoubleQuote) {
            if (i == 0 || std::isspace(static_cast<unsigned char>(input[i - 1]))) {
                return TrimCopy(input.substr(0, i));
            }
        }
    }

    return TrimCopy(input);
}

std::string NormalizeSigmaValue(const std::string& rawValue) {
    std::string value = RemoveYamlInlineComment(TrimCopy(rawValue));
    value = StripOuterQuotes(value);
    value = TrimCopy(value);
    return ToLowerCopy(value);
}

bool EndsWith(const std::string& text, const std::string& suffix) {
    if (suffix.size() > text.size()) {
        return false;
    }

    return std::equal(suffix.rbegin(), suffix.rend(), text.rbegin());
}

bool StartsWith(const std::string& text, const std::string& prefix) {
    if (prefix.size() > text.size()) {
        return false;
    }

    return std::equal(prefix.begin(), prefix.end(), text.begin());
}

std::string JsonEscape(const std::string& input) {
    std::string output;
    output.reserve(input.size());

    for (char c : input) {
        switch (c) {
        case '\\': output += "\\\\"; break;
        case '"': output += "\\\""; break;
        case '\n': output += "\\n"; break;
        case '\r': output += "\\r"; break;
        case '\t': output += "\\t"; break;
        default: output += c; break;
        }
    }

    return output;
}

std::string SeverityToLabel(DetectionSeverity severity) {
    switch (severity) {
    case DetectionSeverity::Critical: return "critical";
    case DetectionSeverity::High: return "high";
    case DetectionSeverity::Medium: return "medium";
    case DetectionSeverity::Low: return "low";
    case DetectionSeverity::Info:
    default:
        return "info";
    }
}

int SeverityPenalty(DetectionSeverity severity) {
    switch (severity) {
    case DetectionSeverity::Critical: return 25;
    case DetectionSeverity::High: return 15;
    case DetectionSeverity::Medium: return 8;
    case DetectionSeverity::Low: return 3;
    case DetectionSeverity::Info:
    default:
        return 1;
    }
}

int ComputeSecurityScoreLocked() {
    int penalty = 0;

    penalty += g_severityCounters[static_cast<int>(DetectionSeverity::Critical)] * SeverityPenalty(DetectionSeverity::Critical);
    penalty += g_severityCounters[static_cast<int>(DetectionSeverity::High)] * SeverityPenalty(DetectionSeverity::High);
    penalty += g_severityCounters[static_cast<int>(DetectionSeverity::Medium)] * SeverityPenalty(DetectionSeverity::Medium);
    penalty += g_severityCounters[static_cast<int>(DetectionSeverity::Low)] * SeverityPenalty(DetectionSeverity::Low);
    penalty += g_severityCounters[static_cast<int>(DetectionSeverity::Info)] * SeverityPenalty(DetectionSeverity::Info);

    return std::max(0, 100 - penalty);
}

std::string SecurityLabelFromScore(int score) {
    if (score >= 90) {
        return "SECURE";
    }
    if (score >= 70) {
        return "FAIR";
    }
    if (score >= 50) {
        return "AT RISK";
    }
    if (score >= 25) {
        return "POOR";
    }

    return "CRITICAL";
}

void PushUniqueValue(std::vector<std::string>& target, const std::string& value) {
    std::string normalized = NormalizeSigmaValue(value);
    if (normalized.empty()) {
        return;
    }

    if (std::find(target.begin(), target.end(), normalized) == target.end()) {
        target.push_back(normalized);
    }
}

std::string ValueAfterColon(const std::string& line) {
    size_t colonPos = line.find(':');
    if (colonPos == std::string::npos || colonPos + 1 >= line.size()) {
        return "";
    }

    return TrimCopy(line.substr(colonPos + 1));
}

bool ParseSigmaRuleFile(const std::filesystem::path& filePath, SigmaLiteRule& outRule) {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        return false;
    }

    enum class SigmaParseMode {
        None,
        ContainsAny,
        ContainsAll,
        StartsWithAny,
        EndsWithAny
    };

    auto updateSelectorModeFromLine = [](
        const std::string& trimmedLine,
        SigmaLiteSelector& selector,
        SigmaParseMode& currentMode
        ) -> bool {
            if (trimmedLine.find("|contains|all:") != std::string::npos) {
                currentMode = SigmaParseMode::ContainsAll;
                PushUniqueValue(selector.containsAll, ValueAfterColon(trimmedLine));
                return true;
            }
            if (trimmedLine.find("|contains:") != std::string::npos) {
                currentMode = SigmaParseMode::ContainsAny;
                PushUniqueValue(selector.containsAny, ValueAfterColon(trimmedLine));
                return true;
            }
            if (trimmedLine.find("|startswith:") != std::string::npos) {
                currentMode = SigmaParseMode::StartsWithAny;
                PushUniqueValue(selector.startsWithAny, ValueAfterColon(trimmedLine));
                return true;
            }
            if (trimmedLine.find("|endswith:") != std::string::npos) {
                currentMode = SigmaParseMode::EndsWithAny;
                PushUniqueValue(selector.endsWithAny, ValueAfterColon(trimmedLine));
                return true;
            }
            if (trimmedLine.rfind("keywords:", 0) == 0) {
                currentMode = SigmaParseMode::ContainsAny;
                PushUniqueValue(selector.containsAny, ValueAfterColon(trimmedLine));
                return true;
            }

            return false;
        };

    auto lineIndent = [](const std::string& lineValue) -> int {
        int count = 0;
        for (char c : lineValue) {
            if (c == ' ') {
                count += 1;
            }
            else if (c == '\t') {
                count += 4;
            }
            else {
                break;
            }
        }
        return count;
        };

    SigmaParseMode currentMode = SigmaParseMode::None;
    bool inDetection = false;
    int detectionIndent = -1;
    int detectionChildIndent = -1;
    std::string currentSelectorName;
    std::string line;

    while (std::getline(file, line)) {
        std::string trimmed = TrimCopy(line);
        if (trimmed.empty()) {
            continue;
        }

        if (trimmed.rfind("title:", 0) == 0) {
            outRule.title = TrimCopy(StripOuterQuotes(ValueAfterColon(trimmed)));
            continue;
        }
        if (trimmed.rfind("level:", 0) == 0) {
            outRule.level = ToLowerCopy(TrimCopy(StripOuterQuotes(ValueAfterColon(trimmed))));
            continue;
        }
        if (trimmed.rfind("detection:", 0) == 0) {
            inDetection = true;
            detectionIndent = lineIndent(line);
            detectionChildIndent = -1;
            currentMode = SigmaParseMode::None;
            currentSelectorName.clear();
            continue;
        }

        if (!inDetection) {
            continue;
        }

        int indent = lineIndent(line);
        if (indent <= detectionIndent && trimmed.find(':') != std::string::npos) {
            break;
        }

        if (detectionChildIndent == -1) {
            detectionChildIndent = indent;
        }

        if (indent == detectionChildIndent && trimmed.find(':') != std::string::npos) {
            std::string selectorKey = ToLowerCopy(TrimCopy(line.substr(0, line.find(':'))));
            std::string selectorValue = ValueAfterColon(trimmed);

            if (selectorKey == "condition") {
                outRule.condition = ToLowerCopy(TrimCopy(StripOuterQuotes(selectorValue)));
                currentSelectorName.clear();
                currentMode = SigmaParseMode::None;
                continue;
            }

            currentSelectorName = selectorKey;
            SigmaLiteSelector& selector = outRule.selectors[currentSelectorName];
            currentMode = SigmaParseMode::None;

            if (currentSelectorName == "keywords") {
                currentMode = SigmaParseMode::ContainsAny;
            }

            if (updateSelectorModeFromLine(trimmed, selector, currentMode)) {
                continue;
            }

            if (!selectorValue.empty()) {
                if (currentMode == SigmaParseMode::None) {
                    currentMode = SigmaParseMode::ContainsAny;
                }
                PushUniqueValue(selector.containsAny, selectorValue);
            }

            continue;
        }

        if (currentSelectorName.empty()) {
            continue;
        }

        SigmaLiteSelector& currentSelector = outRule.selectors[currentSelectorName];

        if (updateSelectorModeFromLine(trimmed, currentSelector, currentMode)) {
            continue;
        }

        if (trimmed.rfind("-", 0) == 0) {
            std::string listValue = TrimCopy(trimmed.substr(1));
            if (listValue.empty()) {
                continue;
            }

            if (updateSelectorModeFromLine(listValue, currentSelector, currentMode)) {
                continue;
            }

            switch (currentMode) {
            case SigmaParseMode::ContainsAny:
                PushUniqueValue(currentSelector.containsAny, listValue);
                break;
            case SigmaParseMode::ContainsAll:
                PushUniqueValue(currentSelector.containsAll, listValue);
                break;
            case SigmaParseMode::StartsWithAny:
                PushUniqueValue(currentSelector.startsWithAny, listValue);
                break;
            case SigmaParseMode::EndsWithAny:
                PushUniqueValue(currentSelector.endsWithAny, listValue);
                break;
            case SigmaParseMode::None:
            default:
                break;
            }
        }
        else {
            std::string inlineValue = ValueAfterColon(trimmed);
            if (!inlineValue.empty()) {
                if (currentMode == SigmaParseMode::None) {
                    currentMode = SigmaParseMode::ContainsAny;
                }
                PushUniqueValue(currentSelector.containsAny, inlineValue);
            }
        }
    }

    if (outRule.title.empty()) {
        outRule.title = filePath.stem().string();
    }
    if (outRule.level.empty()) {
        outRule.level = "medium";
    }
    if (outRule.condition.empty()) {
        outRule.condition = "1 of them";
    }

    return !outRule.selectors.empty();
}

void LoadSigmaRules(const std::string& sigmaDirectory) {
    std::error_code existsError;
    if (!std::filesystem::exists(sigmaDirectory, existsError)) {
        std::cerr << "[*] Sigma directory not found: " << sigmaDirectory << "\n";
        return;
    }

    size_t previousRuleCount = g_sigmaRules.size();
    std::error_code iterError;
    std::filesystem::recursive_directory_iterator it(
        sigmaDirectory,
        std::filesystem::directory_options::skip_permission_denied,
        iterError
    );
    std::filesystem::recursive_directory_iterator end;

    if (iterError) {
        std::cerr << "[*] Failed to iterate Sigma directory: " << sigmaDirectory
            << " (" << iterError.message() << ")\n";
        return;
    }

    for (; it != end; it.increment(iterError)) {
        if (iterError) {
            iterError.clear();
            continue;
        }

        const auto& entry = *it;
        if (!entry.is_regular_file()) {
            continue;
        }

        std::string extension = ToLowerCopy(entry.path().extension().string());
        if (extension != ".yml" && extension != ".yaml") {
            continue;
        }

        SigmaLiteRule parsedRule;
        if (ParseSigmaRuleFile(entry.path(), parsedRule)) {
            g_sigmaRules.push_back(std::move(parsedRule));
        }
    }

    std::cout << "[*] " << (g_sigmaRules.size() - previousRuleCount)
        << " Sigma-Lite rules loaded from " << sigmaDirectory << "\n";
}

bool PatternFoundInFields(const std::vector<std::string>& fields, const std::string& pattern) {
    for (const auto& field : fields) {
        if (field.find(pattern) != std::string::npos) {
            return true;
        }
    }

    return false;
}

bool SelectorMatchesSigmaLite(const SigmaLiteSelector& selector, const std::vector<std::string>& fieldsLower) {
    bool hasOptional = !selector.containsAny.empty() || !selector.startsWithAny.empty() || !selector.endsWithAny.empty();
    bool optionalMatched = false;

    for (const auto& pattern : selector.containsAny) {
        if (PatternFoundInFields(fieldsLower, pattern)) {
            optionalMatched = true;
            break;
        }
    }

    if (!optionalMatched) {
        for (const auto& pattern : selector.startsWithAny) {
            for (const auto& field : fieldsLower) {
                if (StartsWith(field, pattern)) {
                    optionalMatched = true;
                    break;
                }
            }
            if (optionalMatched) {
                break;
            }
        }
    }

    if (!optionalMatched) {
        for (const auto& pattern : selector.endsWithAny) {
            for (const auto& field : fieldsLower) {
                if (EndsWith(field, pattern)) {
                    optionalMatched = true;
                    break;
                }
            }
            if (optionalMatched) {
                break;
            }
        }
    }

    bool requiredMatched = true;
    for (const auto& requiredPattern : selector.containsAll) {
        if (!PatternFoundInFields(fieldsLower, requiredPattern)) {
            requiredMatched = false;
            break;
        }
    }

    if (!requiredMatched) {
        return false;
    }

    if (hasOptional) {
        return optionalMatched;
    }

    return requiredMatched;
}

bool WildcardMatch(const std::string& pattern, const std::string& text) {
    size_t p = 0;
    size_t t = 0;
    size_t star = std::string::npos;
    size_t match = 0;

    while (t < text.size()) {
        if (p < pattern.size() && (pattern[p] == text[t])) {
            p += 1;
            t += 1;
        }
        else if (p < pattern.size() && pattern[p] == '*') {
            star = p++;
            match = t;
        }
        else if (star != std::string::npos) {
            p = star + 1;
            t = ++match;
        }
        else {
            return false;
        }
    }

    while (p < pattern.size() && pattern[p] == '*') {
        p += 1;
    }

    return p == pattern.size();
}

std::vector<std::string> ExpandSelectorPattern(
    const SigmaLiteRule& rule,
    const std::string& rawPattern
) {
    std::string pattern = ToLowerCopy(TrimCopy(rawPattern));
    std::vector<std::string> matchedSelectors;

    if (pattern == "them") {
        for (const auto& [selectorName, _] : rule.selectors) {
            matchedSelectors.push_back(selectorName);
        }
        return matchedSelectors;
    }

    const bool hasWildcard = pattern.find('*') != std::string::npos;
    for (const auto& [selectorName, _] : rule.selectors) {
        if (hasWildcard) {
            if (WildcardMatch(pattern, selectorName)) {
                matchedSelectors.push_back(selectorName);
            }
        }
        else if (selectorName == pattern) {
            matchedSelectors.push_back(selectorName);
        }
    }

    return matchedSelectors;
}

std::vector<std::string> TokenizeCondition(const std::string& condition) {
    std::vector<std::string> tokens;
    std::string current;

    for (char c : condition) {
        if (std::isspace(static_cast<unsigned char>(c))) {
            if (!current.empty()) {
                tokens.push_back(ToLowerCopy(current));
                current.clear();
            }
            continue;
        }

        if (c == '(' || c == ')') {
            if (!current.empty()) {
                tokens.push_back(ToLowerCopy(current));
                current.clear();
            }
            tokens.push_back(std::string(1, c));
            continue;
        }

        current.push_back(c);
    }

    if (!current.empty()) {
        tokens.push_back(ToLowerCopy(current));
    }

    return tokens;
}

bool EvaluateConditionExpression(
    const SigmaLiteRule& rule,
    const std::unordered_map<std::string, bool>& selectorMatches
) {
    std::vector<std::string> tokens = TokenizeCondition(rule.condition);
    if (tokens.empty()) {
        return false;
    }

    size_t index = 0;

    std::function<bool(const std::string&, const std::string&)> evalQuantifier =
        [&](const std::string& quantifier, const std::string& pattern) -> bool {
            std::vector<std::string> selectors = ExpandSelectorPattern(rule, pattern);
            if (selectors.empty()) {
                return false;
            }

            if (quantifier == "1") {
                for (const auto& selectorName : selectors) {
                    auto it = selectorMatches.find(selectorName);
                    if (it != selectorMatches.end() && it->second) {
                        return true;
                    }
                }
                return false;
            }

            if (quantifier == "all") {
                for (const auto& selectorName : selectors) {
                    auto it = selectorMatches.find(selectorName);
                    if (it == selectorMatches.end() || !it->second) {
                        return false;
                    }
                }
                return true;
            }

            return false;
        };

    std::function<bool()> parseExpression;
    std::function<bool()> parseAnd;
    std::function<bool()> parseFactor;
    std::function<bool()> parseAtom;

    parseAtom = [&]() -> bool {
        if (index >= tokens.size()) {
            return false;
        }

        const std::string token = tokens[index];
        if (token == "(") {
            index += 1;
            bool innerResult = parseExpression();
            if (index < tokens.size() && tokens[index] == ")") {
                index += 1;
            }
            return innerResult;
        }

        if ((token == "1" || token == "all") &&
            (index + 2) < tokens.size() &&
            tokens[index + 1] == "of") {
            std::string quantifier = token;
            std::string pattern = tokens[index + 2];
            index += 3;
            return evalQuantifier(quantifier, pattern);
        }

        index += 1;
        auto matchIt = selectorMatches.find(token);
        return matchIt != selectorMatches.end() && matchIt->second;
    };

    parseFactor = [&]() -> bool {
        if (index < tokens.size() && tokens[index] == "not") {
            index += 1;
            return !parseFactor();
        }

        return parseAtom();
    };

    parseAnd = [&]() -> bool {
        bool result = parseFactor();
        while (index < tokens.size() && tokens[index] == "and") {
            index += 1;
            result = result && parseFactor();
        }
        return result;
    };

    parseExpression = [&]() -> bool {
        bool result = parseAnd();
        while (index < tokens.size() && tokens[index] == "or") {
            index += 1;
            result = result || parseAnd();
        }
        return result;
    };

    return parseExpression();
}

bool RuleMatchesSigmaLite(const SigmaLiteRule& rule, const std::vector<std::string>& fieldsLower) {
    std::unordered_map<std::string, bool> selectorMatches;

    for (const auto& [selectorName, selector] : rule.selectors) {
        selectorMatches[selectorName] = SelectorMatchesSigmaLite(selector, fieldsLower);
    }

    return EvaluateConditionExpression(rule, selectorMatches);
}

DetectionSeverity SigmaLevelToSeverity(const std::string& sigmaLevel) {
    const std::string normalizedLevel = ToLowerCopy(sigmaLevel);

    if (normalizedLevel == "critical") {
        return DetectionSeverity::Critical;
    }
    if (normalizedLevel == "high") {
        return DetectionSeverity::High;
    }
    if (normalizedLevel == "medium") {
        return DetectionSeverity::Medium;
    }
    if (normalizedLevel == "low") {
        return DetectionSeverity::Low;
    }

    return DetectionSeverity::Info;
}

void PersistDetectionEvent(
    const std::string& timestamp,
    DetectionSeverity severity,
    UINT32 pid,
    const std::string& method,
    const std::string& message,
    const std::string& details,
    int securityScore
) {
    std::lock_guard<std::mutex> logLock(events_log_mutex);

    std::ofstream outFile(kDefaultEventsLogPath, std::ios::app);
    if (!outFile.is_open()) {
        return;
    }

    outFile
        << "{"
        << "\"timestamp\":\"" << JsonEscape(timestamp) << "\","
        << "\"severity\":\"" << SeverityToLabel(severity) << "\","
        << "\"pid\":" << pid << ","
        << "\"method\":\"" << JsonEscape(method) << "\","
        << "\"security_score\":" << securityScore << ","
        << "\"message\":\"" << JsonEscape(message) << "\","
        << "\"details\":\"" << JsonEscape(details) << "\""
        << "}"
        << "\n";
}

bool ShouldEmitCorrelationAlertLocked(
    UINT32 pid,
    const std::string& method,
    DetectionSeverity severity,
    std::string& outSummary,
    std::string& outDetails
) {
    if (pid == 0 || pid == curPid) {
        return false;
    }

    const time_t now = time(0);
    auto& history = g_recentEventsByPid[pid];
    history.push_back({ now, method, severity });

    const time_t correlationWindowSeconds = 120;
    while (!history.empty() && (now - history.front().timestamp) > correlationWindowSeconds) {
        history.pop_front();
    }

    if (history.size() < 2) {
        return false;
    }

    std::unordered_set<std::string> uniqueMethods;
    bool hasHighOrCritical = false;

    for (const auto& event : history) {
        uniqueMethods.insert(event.method);
        if (event.severity == DetectionSeverity::High || event.severity == DetectionSeverity::Critical) {
            hasHighOrCritical = true;
        }
    }

    if (uniqueMethods.size() < 2 || !hasHighOrCritical) {
        return false;
    }

    const time_t alertCooldownSeconds = 300;
    auto lastAlertIt = g_lastCorrelationAlertByPid.find(pid);
    if (lastAlertIt != g_lastCorrelationAlertByPid.end() && (now - lastAlertIt->second) < alertCooldownSeconds) {
        return false;
    }

    g_lastCorrelationAlertByPid[pid] = now;

    std::string date_time_str = BuildTimestamp();
    outSummary = std::to_string(tab_1_menu_items.size()) +
        " - [!] [Alert] | " + date_time_str +
        " | Method: Correlation Engine" +
        " | Multi-method detection chain on PID " + std::to_string(pid);

    outDetails = "Date & Time: " + date_time_str +
        " | PID: " + std::to_string(pid) +
        " | Method: Correlation Engine" +
        " | Trigger: multiple detection methods observed within 120 seconds.";

    return true;
}

void PushUiDetectionEvent(
    const std::string& message,
    const std::string& details,
    const std::string& method,
    UINT32 pid,
    DetectionSeverity severity,
    bool allowCorrelation = true
) {
    std::string timestamp = BuildTimestamp();
    int securityScore = 100;
    bool emitCorrelationAlert = false;
    std::string correlationSummary;
    std::string correlationDetails;

    {
        std::lock_guard<std::mutex> lock(security_event_mutex);

        tab_1_menu_items.push_back(message);
        detectEventsDetails.push_back(details);
        g_severityCounters[static_cast<int>(severity)] += 1;

        securityScore = ComputeSecurityScoreLocked();
        tab_values[0] = "Detection Events (" + std::to_string(tab_1_menu_items.size()) + ") | Score: " +
            std::to_string(securityScore) + " (" + SecurityLabelFromScore(securityScore) + ")";
        should_update = true;

        if (allowCorrelation) {
            emitCorrelationAlert = ShouldEmitCorrelationAlertLocked(
                pid,
                method,
                severity,
                correlationSummary,
                correlationDetails
            );
        }

        auto tab_toggle = Toggle(&tab_values, &tab_selected);
        screen.PostEvent(Event::Custom);
    }

    PersistDetectionEvent(timestamp, severity, pid, method, message, details, securityScore);

    if (emitCorrelationAlert) {
        PushUiDetectionEvent(
            correlationSummary,
            correlationDetails,
            "Method: Correlation Engine",
            pid,
            DetectionSeverity::Critical,
            false
        );
    }
}

void NotifySigmaMatches(
    UINT32 pid,
    const std::string& procName,
    const std::vector<std::string>& candidateFields,
    const std::string& sourceContext
) {
    if (g_sigmaRules.empty() || pid == curPid || candidateFields.empty()) {
        return;
    }

    std::vector<std::string> fieldsLower;
    fieldsLower.reserve(candidateFields.size());
    for (const auto& field : candidateFields) {
        std::string normalizedField = ToLowerCopy(TrimCopy(field));
        if (!normalizedField.empty()) {
            fieldsLower.push_back(std::move(normalizedField));
        }
    }

    if (fieldsLower.empty()) {
        return;
    }

    const std::string contextKey = ToLowerCopy(sourceContext) + "|" + fieldsLower.front();
    int emittedMatches = 0;
    const int maxMatchesPerEvent = 2;

    for (const auto& rule : g_sigmaRules) {
        if (!RuleMatchesSigmaLite(rule, fieldsLower)) {
            continue;
        }

        const std::string dedupKey = rule.title + "|" + std::to_string(pid) + "|" + contextKey;
        if (g_sigmaMatchDedup.find(dedupKey) != g_sigmaMatchDedup.end()) {
            continue;
        }
        g_sigmaMatchDedup.insert(dedupKey);

        const std::string dateTime = BuildTimestamp();
        const std::string message = std::to_string(tab_1_menu_items.size()) +
            " - [!] [Alert] | " + dateTime +
            " | " + procName +
            " | Method: Sigma-Lite Rule Matching" +
            " | Rule: " + rule.title;

        const std::string details = "Date & Time: " + dateTime +
            " | " + procName +
            " | PID: " + std::to_string(pid) +
            " | Method: Sigma-Lite Rule Matching" +
            " | Rule: " + rule.title +
            " | Level: " + rule.level +
            " | Source Context: " + sourceContext;

        PushUiDetectionEvent(
            message,
            details,
            "Method: Sigma-Lite Rule Matching",
            pid,
            SigmaLevelToSeverity(rule.level)
        );

        emittedMatches += 1;
        if (emittedMatches >= maxMatchesPerEvent) {
            break;
        }
    }
}

void NotifyLolDriverMatch(PKERNEL_STRUCTURED_NOTIFICATION notif, const std::string& fullPath) {
    if (lolDriverNames.empty() || fullPath.empty()) {
        return;
    }

    std::filesystem::path fsPath(fullPath);
    const std::string fileName = ToLowerCopy(fsPath.filename().string());
    const std::string extension = ToLowerCopy(fsPath.extension().string());

    if (extension != ".sys") {
        return;
    }

    if (lolDriverNames.find(fileName) == lolDriverNames.end()) {
        return;
    }

    const std::string normalizedPath = ToLowerCopy(fsPath.lexically_normal().string());
    if (detectedLolDriverPaths.find(normalizedPath) != detectedLolDriverPaths.end()) {
        return;
    }

    detectedLolDriverPaths.insert(normalizedPath);

    const std::string date_time_str = BuildTimestamp();
    const UINT32 pid = static_cast<UINT32>(notif->pid);
    const std::string procName = std::string(notif->procName);

    const std::string message = std::to_string(tab_1_menu_items.size()) +
        " - [!] [Warning] | " + date_time_str +
        " | " + procName +
        " | Method: LOLDrivers Lookup" +
        " | Flagged driver file: " + fileName;

    const std::string details = "Date & Time: " + date_time_str +
        " | " + procName +
        " | PID: " + std::to_string(pid) +
        " | Method: LOLDrivers Lookup" +
        " | Driver: " + fileName +
        " | Path: " + fullPath;

    PushUiDetectionEvent(
        message,
        details,
        "Method: LOLDrivers Lookup",
        pid,
        DetectionSeverity::Medium
    );
}

bool LoadLolDriversCache(const std::string& cachePath) {
    std::ifstream cacheFile(cachePath);
    if (!cacheFile.is_open()) {
        std::cerr << "[*] LOLDrivers cache not found at: " << cachePath << "\n";
        return false;
    }

    std::string rawJson(
        (std::istreambuf_iterator<char>(cacheFile)),
        std::istreambuf_iterator<char>()
    );

    std::regex fileNameRegex(R"("n"\s*:\s*"([^"]+)")");
    std::sregex_iterator it(rawJson.begin(), rawJson.end(), fileNameRegex);
    std::sregex_iterator end;

    size_t beforeLoad = lolDriverNames.size();

    for (; it != end; ++it) {
        if (it->size() > 1) {
            std::string driverName = ToLowerCopy((*it)[1].str());
            if (!driverName.empty()) {
                lolDriverNames.insert(driverName);
            }
        }
    }

    std::cout << "[*] " << (lolDriverNames.size() - beforeLoad)
        << " LOLDrivers names loaded from " << cachePath << "\n";

    return !lolDriverNames.empty();
}


int yr_callback_function_file(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data)
{
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        KERNEL_STRUCTURED_NOTIFICATION* notif = (PKERNEL_STRUCTURED_NOTIFICATION)user_data;
        UINT32 pid = (UINT32)notif->pid;

        if (pid == curPid) {
            return CALLBACK_CONTINUE;
        }

        DWORD bytesReturned;
        BOOL endRes = DeviceIoControl(
            hBeotmDevice,
            END_THAT_PROCESS,
            &pid,
            sizeof(pid),
            nullptr,
            0,
            &bytesReturned,
            nullptr
        );

        time_t now = time(0);
        struct tm timeinfo;
        localtime_s(&timeinfo, &now);
        char date_time[80];
        strftime(date_time, sizeof(date_time), "%Y-%m-%d %H:%M:%S", &timeinfo);

        std::string date_time_str = date_time;
        std::string method = "Method: In-Memory Loaded Image Analysis";

        std::string msgCatch;
        std::string details;

        if (endRes) {

            msgCatch = std::to_string(tab_1_menu_items.size()) + " - [!] " + date_time_str + " | " + method + " | YARA rule Identifier: " + std::string(((YR_RULE*)message_data)->identifier) + " | Process was terminated";

            details = "Date & Time: " + date_time_str +
                " | PID: " + std::to_string(pid) +
                " | Method: In-Memory Loaded Image Analysis" +
                " | YARA rule Identifier: " + std::string(((YR_RULE*)message_data)->identifier) +
                " | Process was terminated successfully.";
        }
        else {

            msgCatch = std::to_string(tab_1_menu_items.size()) + " - [!] " + date_time_str + " | Memory Mapped Image | Identified: " + std::string(((YR_RULE*)message_data)->identifier) + " | (!) Failed to kill process";

            details = "Date & Time: " + date_time_str +
                " | PID: " + std::to_string(pid) +
                " | Method: In-Memory Loaded Image Analysis" +
                " | YARA rule Identifier: " + std::string(((YR_RULE*)message_data)->identifier) +
                " | (!) Process termination failed.";
        }

        PushUiDetectionEvent(
            msgCatch,
            details,
            "Method: In-Memory Loaded Image Analysis",
            pid,
            DetectionSeverity::Critical
        );

        return 1;

    }

    if (message == CALLBACK_MSG_SCAN_FINISHED) {
        char* fileName = (char*)user_data;

        if (benignFSPaths.find(fileName) == benignFSPaths.end()) {

            //printf("[+] Adding to benignFSPaths: %s\n", fileName);
            benignFSPaths.insert(fileName);

            return CALLBACK_CONTINUE;
        }
    }

    return CALLBACK_CONTINUE;
}

int yr_callback_function_byte_stream(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data
)
{
    if (message == CALLBACK_MSG_RULE_MATCHING) {

        PKERNEL_STRUCTURED_BUFFER structBuffer = (PKERNEL_STRUCTURED_BUFFER)user_data;

        UINT32 pid = (UINT32)structBuffer->pid;
        char* procName = structBuffer->procName;

        if (pid == curPid) {
            return CALLBACK_CONTINUE;
        }

        DWORD bytesReturned;
        BOOL endRes = DeviceIoControl(
            hBeotmDevice,
            END_THAT_PROCESS,
            &pid,
            sizeof(pid),
            nullptr,
            0,
            &bytesReturned,
            nullptr
        );

        time_t now = time(0);
        struct tm timeinfo;
        localtime_s(&timeinfo, &now);
        char date_time[80];
        strftime(date_time, sizeof(date_time), "%Y-%m-%d %H:%M:%S", &timeinfo);

        std::string date_time_str = date_time;
        std::string msgCatch;
        std::string details;

        std::string rule_identifier = std::string(((YR_RULE*)message_data)->identifier);

        if (endRes) {

            msgCatch = std::to_string(tab_1_menu_items.size()) +
                " - [!] [Alert] | " + date_time_str +
                " | " + std::string(structBuffer->procName) +
                " | Byte Stream Analysis | Identified: " + rule_identifier +
                "\n\n | Process with PID " + std::to_string(pid) + " has been terminated.";

            details = "Date & Time: " + date_time_str +
                " | " + std::string(structBuffer->procName) +
                " | PID: " + std::to_string(pid) +
                " | Method: Byte Stream Analysis" +
                " | YARA rule Identifier: " + rule_identifier +
                " | Process was terminated successfully.";
        }
        else {

            msgCatch = std::to_string(tab_1_menu_items.size()) +
                " - [!] [Alert] | " + date_time_str +
                " | " + std::string(structBuffer->procName) +
                " | Byte Stream Analysis | Identified: " + rule_identifier +
                "\n\n | (!) Failed to terminate process with PID " + std::to_string(pid);

            details = "Date & Time: " + date_time_str +
                " | PID: " + std::to_string(pid) +
                " | " + std::string(structBuffer->procName) +
                " | Method: Byte Stream Analysis" +
                " | YARA rule Identifier: " + rule_identifier +
                " | (!) Process termination failed.";
        }

        PushUiDetectionEvent(
            msgCatch,
            details,
            "Method: Byte Stream Analysis",
            pid,
            DetectionSeverity::Critical
        );
    }

    return CALLBACK_CONTINUE;
}

UINT lastNotifiedStackSpoofPid = 0;

int Notify(PKERNEL_STRUCTURED_NOTIFICATION notif, char* msg) {

    time_t now = time(0);
    struct tm timeinfo;
    localtime_s(&timeinfo, &now);
    char date_time[80];
    strftime(date_time, sizeof(date_time), "%Y-%m-%d %H:%M:%S", &timeinfo);

    UINT32 pid = (UINT32)notif->pid;

    if (pid == curPid) {
        return 0;
    }

    std::string date_time_str = date_time;
    std::string msgCatch;
    std::string details;
    std::string targetedProc = "";
    std::string method;

    if (notif->ProcVadCheck) {
        method = "Method: Process VAD Tree Inspection";
    }
    else if (notif->StackBaseVadCheck) {
        method = "Method: Stack Base + VAD Inspection";
    }
    else if (notif->CallingProcPidCheck) {
        method = "Method: Calling Process PID Inspection";
    }
    else if (notif->SeAuditInfoCheck) {
        method = "Method: Process Audit Info Inspection";
    }
    else if (notif->ImageLoadPathCheck) {
        method = "Method: Image Load Path Inspection";
    }
    else if (notif->ObjectCheck) {
        method = "Method: Object Operation Inspection";
        targetedProc = " -> " + std::string(notif->targetProcName) + " ";
    }
    else if (notif->RegCheck) {
        method = "Method: Registry Operation Inspection";
    }
    else if (notif->SyscallCheck) {
        method = "Method: Syscall Integrity Inspection";
    }
    else if (notif->ShadowStackCheck) {

        if (lastNotifiedStackSpoofPid == pid) {
            return 0;
        }

        lastNotifiedStackSpoofPid = pid;
        method = "Method: Shadow Stack Inspection";
    }

    if (notif->Critical) {

        try {
            DWORD bytesReturned;
            BOOL endRes = DeviceIoControl(
                hBeotmDevice,
                END_THAT_PROCESS,
                &pid,
                sizeof(pid),
                nullptr,
                0,
                &bytesReturned,
                nullptr
            );

            if (endRes) {

                msgCatch = std::to_string(tab_1_menu_items.size()) +
                    " - [!] [Alert] | " + date_time_str +
                    " | " + notif->procName +
                    " | " + method +
                    " | " + (char*)msg;

                msgCatch += " | Process with PID " + std::to_string(pid) + " has been terminated.";

                details = "Date & Time: " + date_time_str +
                    " | " + notif->procName +
                    " | " + method +
                    " | " + (char*)msg +
                    " | PID: " + std::to_string(pid);

                details += " | Process was terminated.";
            }
            else {

                msgCatch = std::to_string(tab_1_menu_items.size()) +
                    " - [!] [Alert] | " + date_time_str +
                    " | " + notif->procName +
                    " | " + method +
                    " | " + (char*)msg +
                    " | (!) Failed to terminate process with PID " + std::to_string(pid);

                details = "Date & Time: " + date_time_str +
                    " | " + notif->procName +
                    " | " + method +
                    " | " + (char*)msg +
                    " | PID: " + std::to_string(pid) +
                    " | (!) Process termination failed.";
            }

            PushUiDetectionEvent(
                msgCatch,
                details,
                method,
                pid,
                DetectionSeverity::Critical
            );
        }
        catch (std::exception& e) {
            std::cerr << "[!] Exception caught: " << e.what() << std::endl;
        }

    }
    else if (notif->Warning) {

        msgCatch = std::to_string(tab_1_menu_items.size()) +
            " - [*] [Warning] | " + date_time_str +
            " | " + method +
            " | " + notif->procName +
            " | " + (char*)msg;

        details = "Date & Time: " + date_time_str +
            " | " + notif->procName +
            " | " + method +
            " | " + (char*)msg +
            " | PID: " + std::to_string(pid);

        PushUiDetectionEvent(
            msgCatch,
            details,
            method,
            pid,
            DetectionSeverity::Medium
        );

    }
    else if (notif->Info) {
        msgCatch = std::to_string(tab_1_menu_items.size()) +
            " - [i] [Info] | " + date_time_str +
            " | " + method +
            " | " + notif->procName +
            " | " + (char*)msg;

        details = "Date & Time: " + date_time_str +
            " | " + notif->procName +
            " | " + method +
            " | " + (char*)msg +
            " | PID: " + std::to_string(pid);

        PushUiDetectionEvent(
            msgCatch,
            details,
            method,
            pid,
            DetectionSeverity::Info
        );
    }

    return 0;
}

void setConsoleColor(WORD color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

void AddYaraRulesFromDirectory(const std::string& rulesDirectory) {
    std::error_code existsError;
    if (!std::filesystem::exists(rulesDirectory, existsError)) {
        std::cerr << "[*] YARA directory not found: " << rulesDirectory << "\n";
        return;
    }

    std::error_code iterError;
    std::filesystem::recursive_directory_iterator iter(
        rulesDirectory,
        std::filesystem::directory_options::skip_permission_denied,
        iterError
    );
    std::filesystem::recursive_directory_iterator end;

    if (iterError) {
        std::cerr << "[*] Failed to iterate YARA directory: " << rulesDirectory
            << " (" << iterError.message() << ")\n";
        return;
    }

    for (; iter != end; iter.increment(iterError)) {
        if (iterError) {
            iterError.clear();
            continue;
        }

        const auto& entry = *iter;
        if (!entry.is_regular_file()) {
            continue;
        }

        std::string extension = ToLowerCopy(entry.path().extension().string());
        if (extension != ".yar" && extension != ".yara") {
            continue;
        }

        std::string normalizedRulePath = ToLowerCopy(entry.path().lexically_normal().string());
        if (loadedYaraRulePaths.find(normalizedRulePath) != loadedYaraRulePaths.end()) {
            continue;
        }

        FILE* rule_file;
        if (fopen_s(&rule_file, entry.path().string().c_str(), "r") != 0 || rule_file == NULL) {
            std::cerr << "Failed to open Yara rule: " << entry.path().string() << "\n";
            continue;
        }

        if (yr_compiler_add_file(compiler, rule_file, NULL, entry.path().string().c_str()) != ERROR_SUCCESS) {
            std::cerr << "Failed to add Yara rule: " << entry.path().string() << "\n";
            fclose(rule_file);
            continue;
        }

        fclose(rule_file);
        loadedYaraRulePaths.insert(normalizedRulePath);
        yara_rules_count += 1;

        setConsoleColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
        printf("\t [+] Adding Yara rule: %s\n", entry.path().string().c_str());
        setConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }
}

VOID InitYara(const std::vector<std::string>& yaraRulesDirectories) {

    if (yr_initialize() != ERROR_SUCCESS) {
        std::cerr << "Failed to initialize Yara\n";
        system("pause");
    }

    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
        std::cerr << "Failed to create Yara compiler\n";
        system("pause");
        return;
    }

    for (const auto& directory : yaraRulesDirectories) {
        AddYaraRulesFromDirectory(directory);
    }

    int result = yr_compiler_get_rules(compiler, &rules);

    if (result != 0) {
        std::cerr << "Error retrieving compiled rules" << std::endl;
        system("pause");
        yr_compiler_destroy(compiler);
        yr_finalize();
        return;
    }

    int scan_res = yr_scanner_create(rules, &scanner);

    if (scan_res != 0 || scanner == nullptr) {
        std::cerr << "Error while creating a scanner" << std::endl;
        system("pause");
        return;
    }
}

auto detail_panel_content = [&]() {

    if (!detectEventsDetails.empty()) {
        return paragraph(detectEventsDetails.at(tab_1_selected));
    }

    return paragraph(" ") | center;

    };

auto tab_1_container = Container::Vertical({
    Renderer(tab_1_menu, [&] {

        auto main_panel = vbox({
            text("Detection Events:") | bold | color(Color::Red),
            tab_1_menu->Render() | frame | border | size(HEIGHT, EQUAL, 60),
        });

        auto details_panel = vbox({
            text("Details:") | bold | color(Color::Yellow),
            detail_panel_content() | border | size(HEIGHT, EQUAL, 10),
            });

        return vbox({
            main_panel | flex,
            details_panel,
        }) | border;

        /*return tab_1_menu->Render() |
               size(HEIGHT, GREATER_THAN, 10) |
               frame | vscroll_indicator | focus | color(Color::Red);*/
    })
    });

void ConsumeIOCTLData(LPCWSTR deviceName, DWORD ioctlCode, int sleepDurationMs) {

    hBeotmDevice = CreateFileW(
        deviceName,
        GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hBeotmDevice == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open device: " << GetLastError() << std::endl;
        exit(-1);
        ;
    }

    DWORD bufferSize = 1024 * 1024;
    BYTE* buffer = (BYTE*)malloc(bufferSize);
    if (!buffer) {
        std::cerr << "Failed to allocate buffer" << std::endl;
        CloseHandle(hBeotmDevice);
        return;
    }

    const int maxRetries = 1000000000;
    int retryCount = 0;

    while (retryCount < maxRetries) {

        DWORD bytesReturned = 0;
        BOOL result = DeviceIoControl(
            hBeotmDevice,
            ioctlCode,
            nullptr,
            0,
            buffer,
            bufferSize,
            &bytesReturned,
            nullptr
        );

        if (result) {

            if (ioctlCode == BEOTM_RETRIEVE_DATA_BYTE) {

                if (bytesReturned < sizeof(KERNEL_STRUCTURED_BUFFER)) {
                    std::cerr << "Invalid buffer size returned" << std::endl;
                    break;
                }

                KERNEL_STRUCTURED_BUFFER* structuredBuffer = (PKERNEL_STRUCTURED_BUFFER)buffer;
                BYTE* bufferData = (BYTE*)(buffer + sizeof(KERNEL_STRUCTURED_BUFFER));

                yr_rules_scan_mem(
                    rules,
                    bufferData,
                    structuredBuffer->bufSize,
                    0,
                    (YR_CALLBACK_FUNC)yr_callback_function_byte_stream,
                    (void*)structuredBuffer,
                    0
                );

            }
            else if (ioctlCode == BEOTM_RETRIEVE_DATA_BUFFER) {

                std::cout << "Buffer" << std::endl;

            }
            else if (ioctlCode == BEOTM_RETRIEVE_DATA_FILE) {

                if (bytesReturned < sizeof(KERNEL_STRUCTURED_NOTIFICATION)) {
                    std::cerr << "Invalid buffer size returned" << std::endl;
                    break;
                }

                if (buffer && bufferSize > 0) {

                    PKERNEL_STRUCTURED_NOTIFICATION notif = (PKERNEL_STRUCTURED_NOTIFICATION)buffer;
                    char* msg = (char*)(buffer + sizeof(KERNEL_STRUCTURED_NOTIFICATION));

                    if (msg != NULL) {

                        if (notif->isPath) {

                            std::string litFileName = msg;
                            std::string fullPath = QueryDosDevicePath(litFileName);
                            if (fullPath.empty()) {
                                fullPath = litFileName;
                            }

                            NotifyLolDriverMatch(notif, fullPath);
                            NotifySigmaMatches(
                                static_cast<UINT32>(notif->pid),
                                std::string(notif->procName),
                                { fullPath, litFileName, std::string(notif->procName) },
                                "file_path_notification"
                            );

                            if (benignFSPaths.find(fullPath) != benignFSPaths.end()) {
                                continue;
                            }

                            int fileScanRes = yr_rules_scan_file(
                                rules,
                                fullPath.c_str(),
                                0,
                                (YR_CALLBACK_FUNC)yr_callback_function_file,
                                (void*)notif,
                                0
                            );
                        }
                        else {
                            NotifySigmaMatches(
                                static_cast<UINT32>(notif->pid),
                                std::string(notif->procName),
                                { std::string(msg), std::string(notif->procName) },
                                "generic_notification"
                            );

                            Notify(notif, msg);
                        }
                    }
                }
            }
        }

        Sleep(sleepDurationMs);
    }

    free(buffer);
    CloseHandle(hBeotmDevice);
}

std::string GetLastErrorAsString() {
    DWORD errorMessageID = GetLastError();
    if (errorMessageID == 0)
        return std::string();

    LPSTR messageBuffer = nullptr;
    size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

    std::string message(messageBuffer, size);

    LocalFree(messageBuffer);

    return message;
}

SC_HANDLE hService;
SC_HANDLE hSCManager;

void UninstallBeotmDriver() {
    if (hService) {
        SERVICE_STATUS status;
        if (ControlService(hService, SERVICE_CONTROL_STOP, &status)) {
            std::wcout << L"Service stopped successfully." << std::endl;
        }
        else {
            std::wcout << L"Failed to stop service. Error: " << GetLastError() << std::endl;
        }

        if (DeleteService(hService)) {
            std::wcout << L"Service deleted successfully." << std::endl;
        }
        else {
            std::wcout << L"Failed to delete service. Error: " << GetLastError() << std::endl;
        }

        CloseServiceHandle(hService);
        hService = nullptr;
    }

    if (hSCManager) {
        CloseServiceHandle(hSCManager);
        hSCManager = nullptr;
    }
}


bool InstallBeotmDriver(
    const std::wstring& drvName,
    const std::wstring& drvPath
) {

    hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);

    if (!hSCManager) {
        std::wcout << L"Failed to open service control manager. Error: " << GetLastError() << std::endl;
        return false;
    }

    hService = CreateServiceW(
        hSCManager,
        drvName.c_str(),
        drvName.c_str(),
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        drvPath.c_str(),
        NULL,
        NULL,
        NULL,
        NULL,
        NULL
    );


    if (!hService) {
        if (GetLastError() == ERROR_SERVICE_EXISTS) {
            std::wcout << L"Service already exists, opening existing service..." << std::endl;
            hService = OpenService(hSCManager, drvName.c_str(), SERVICE_START);
            if (!hService) {
                std::wcerr << L"Failed to open existing service. Error: " << GetLastError() << std::endl;
                CloseServiceHandle(hSCManager);
                return false;
            }
        }
        else {
            std::wcerr << L"Failed to create service. Error: " << GetLastError() << std::endl;
            CloseServiceHandle(hSCManager);
            return false;
        }
    }

    if (!StartService(hService, 0, nullptr)) {
        if (GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
            std::wcerr << L"Failed to start service. Error: " << GetLastError() << std::endl;
            std::cerr << GetLastErrorAsString() << std::endl;

            CloseServiceHandle(hService);
            CloseServiceHandle(hSCManager);
            return false;
        }
    }

    std::wcout << L"Driver installed and started successfully!" << std::endl;

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return true;

}

void SignalHandler(int signal) {
    if (signal == SIGINT) {
        std::wcout << L"Ctrl+C detected. Uninstalling driver..." << std::endl;
        UninstallBeotmDriver();
        exit(0);
    }
}

VOID ShowUI() {

    auto screen = ScreenInteractive::Fullscreen();

    auto tab_container = Container::Tab(
        {
            tab_1_container,
            //Renderer([] { return text("Tab 2 Content"); }),
            //Renderer([] { return text("Tab 3 Content"); }),
            Renderer([&] {
                if (tab_values[tab_selected] == "About") {
                    auto lines = SplitLines(startupAsciiTitle);
                    std::vector<Element> ascii_elements;
                    for (const auto& line : lines) {
                        ascii_elements.push_back(text(line));
                    }
                    return vbox(ascii_elements) | center | xflex | yflex;
                }
                return text("");
            }),
        },
        &tab_selected);


    auto container = Container::Vertical({
    tab_toggle,
    tab_container,
        });

    auto renderer = Renderer(container, [&] {
        return vbox({
                   tab_toggle->Render(),
                   separator(),
                   tab_container->Render() | size(HEIGHT, LESS_THAN, 40),
            }) |
            border;
        });

    std::thread threadByte([]() {
        ConsumeIOCTLData(L"\\\\.\\Beotm", BEOTM_RETRIEVE_DATA_BYTE, 5);
        });

    std::thread threadFile([]() {
        ConsumeIOCTLData(L"\\\\.\\Beotm", BEOTM_RETRIEVE_DATA_FILE, 5);
        });

    try {
        screen.Loop(renderer);
    }
    catch (const std::exception& e) {
        std::cerr << "[!] Exception caught: " << e.what() << std::endl;
    }
    catch (...) {
        std::cerr << "[!] Unknown exception caught" << std::endl;
    }

    auto event_handler = CatchEvent(tab_1_container, [&](Event event) {
        if (event == Event::ArrowUp) {
            tab_1_selected = (tab_1_selected > 0) ? tab_1_selected - 1 : tab_1_menu_items.size() - 1;
            return true;
        }
        if (event == Event::ArrowDown) {
            tab_1_selected = (tab_1_selected + 1) % tab_1_menu_items.size();
            return true;
        }
        return false;
        });

    std::thread refresh_thread([&screen]() {
        while (true) {
            std::this_thread::sleep_for(10ms);
            screen.PostEvent(Event::Custom);
        }
        });

    threadByte.join();
    threadFile.join();
}

int main(int argc, char* argv[]) {

    std::signal(SIGINT, SignalHandler);

    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <path to driver> [path to YARA rules directory] [path to LOLDrivers cache] [path to Sigma rules directory]\n";
        return 1;
    }

    std::wstring driverPath = std::wstring(argv[1], argv[1] + strlen(argv[1]));
    std::wstring driverName = L"BeotmDrv";
    std::vector<std::string> yaraRulesDirectories;

    if (argc >= 3 && strlen(argv[2]) > 0) {
        yaraRulesDirectories.push_back(argv[2]);
    }

    yaraRulesDirectories.push_back(kLoadedPotatoYaraRulesDir);

    std::string lolDriversCachePath = kLoadedPotatoLolDriversCachePath;
    if (argc >= 4 && strlen(argv[3]) > 0) {
        lolDriversCachePath = argv[3];
    }

    std::string sigmaRulesDirectory = kLoadedPotatoSigmaRulesDir;
    if (argc >= 5 && strlen(argv[4]) > 0) {
        sigmaRulesDirectory = argv[4];
    }

    std::wstring fullPath = GetFullPath(driverPath);

    if (!InstallBeotmDriver(driverName, fullPath)) {
        std::wcerr << L"Failed to install driver." << std::endl;
        std::cerr << GetLastErrorAsString() << std::endl;
        return 1;
    }

    curPid = static_cast<UINT32>(GetCurrentProcessId());

    std::cout << "[*] Loading LOLDrivers cache...\n";
    LoadLolDriversCache(lolDriversCachePath);
    std::cout << "[*] Loading Sigma rules...\n";
    LoadSigmaRules(sigmaRulesDirectory);

    printf("[*] Loading YARA rules...\n");

    InitYara(yaraRulesDirectories);

    printf("[*] %d Yara Rules Loaded & Compiled\n", yara_rules_count);
    system("pause");

    ShowUI();

    return 0;
}
