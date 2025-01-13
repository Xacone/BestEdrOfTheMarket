#include "Utils.h"
//
//std::string QueryDosDevicePath(const std::string& devicePath) {
//    char driveLetter = 'A';
//    char deviceName[256];
//    char targetPath[1024];
//    DWORD result;
//
//    for (driveLetter = 'A'; driveLetter <= 'Z'; ++driveLetter) {
//        std::string drive = std::string(1, driveLetter) + ":";
//        result = QueryDosDeviceA(drive.c_str(), deviceName, 256);
//        if (result != 0) {
//            if (devicePath.find(deviceName) == 0) {
//                std::string fullPath = drive + devicePath.substr(strlen(deviceName));
//                return fullPath;
//            }
//        }
//    }
//    return "";
//}
