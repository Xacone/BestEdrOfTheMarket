#include "Startup.h"

std::string startupAsciiTitle = R"( ____            _     _____ ____  ____     ___   __   _____ _          
| __ )  ___  ___| |_  | ____|  _ \|  _ \   / _ \ / _| |_   _| |__   ___ 
|  _ \ / _ \/ __| __| |  _| | | | | |_) | | | | | |_    | | | '_ \ / _ \
| |_) |  __/\__ \ |_  | |___| |_| |  _ <  | |_| |  _|   | | | | | |  __/
|____/_\___||___/\__| |_____|____/|_| \_\  \___/|_|     |_| |_| |_|\___|     1.1.0
|  \/  | __ _ _ __| | _____| |_                                         
| |\/| |/ _` | '__| |/ / _ \ __|                                        
| |  | | (_| | |  |   <  __/ |_           Yazidou - github.com/Xacone                              
|_|  |_|\__,_|_|  |_|\_\___|\__|                                        )";


void printStartupAsciiTitle() {
	std::cout << startupAsciiTitle << std::endl;
}

void printHelp() {
	std::cout << "\033[0;38;2;135;206;250m";
	printStartupAsciiTitle();
	std::cout << "\033[0m";
	std::cout

		<< "\n\t\t\033[0;38;2;128;0;32mhttps://github.com/Xacone/BestEdrOfTheMarket\033[0m"
		<< "\n\n\tUsage: BestEdrOfTheMarket.exe [args]"
		<< "\n\n\t\t /help : Shows this help message and exits"
		<< "\n\t\t /v Verbosity \n"
		<< "\n\t\t /iat IAT hooking "
		<< "\n\t\t /stack Threads call stack monitoring"
		<< "\n\t\t /boost Boosting RIP refresh rate (increase load on CPU !)"
		<< "\n\t\t /heap Heap monitoring"
		<< "\n\t\t /nt Inline Nt-level hooking"
		<< "\n\t\t /k32 Inline Kernel32/Kernelbase hooking"
		<< "\n\t\t /ssn SSN crushing"
		
		/*
		<< "\n\t\t /amsi AMSI patching mitigation"
		<< "\n\t\t /etw ETW patching mitigation"
		<< "\n\t\t /rop ROP mitigation"
		*/

		<< std::endl;
}

std::string caramelle() {
	return R"(
	  __      _
	o'')}____//
	 `_/      )
	 (_(_/-(_/
	)";
}