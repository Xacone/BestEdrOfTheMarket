/**
* @file Startup.cpp
* @brief Texts & banners utilities
*/


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


std::string startupHelp = R"(

                      .            .            .            .
                .   .      .    .     .     .    .      .   .      . .  .  -+-

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
         |____/_\___||___/\__| |_____|____/|_| \_\  \___/|_|     |_| |_| |_|\___|     1.1.0
         |  \/  | __ _ _ __| | _____| |_                                         
         | |\/| |/ _` | '__| |/ / _ \ __|                                        
         | |  | | (_| | |  |   <  __/ |_           Yazidou - github.com/Xacone                              
         |_|  |_|\__,_|_|  |_|\_\___|\__|                                        
)";


void printStartupAsciiTitle() {
	std::cout << startupAsciiTitle << std::endl;
}

void printAsciiArtTitle() {
	std::cout << startupHelp << std::endl;
}

//**

void printHelp() {
    printAsciiArtTitle();
	std::cout
		<< "\n\t\t\t\033[0;38;2;128;0;32mhttps://github.com/Xacone/BestEdrOfTheMarket\033[0m"
		<< "\n\n\tUsage: BestEdrOfTheMarket.exe [args]\n"
		<< "\n\t\t /v : Verbosity"
        << "\n\t\t /yara : Enabling YARA rules"
        << "\n\t\t /nt : Inline Nt-level hooking"
        << "\n\t\t /k32 : Inline Kernel32/Kernelbase hooking"
		<< "\n\t\t /iat : IAT hooking"
		<< "\n\t\t /stack : Threads call stack monitoring"
		<< "\n\t\t /heap : Heap monitoring (to use with /k32, /iat or /nt)"
        << "\n\t\t /patch : ETW/AMSI patching detection"
        << "\n\t\t /direct : Direct Syscalls Detection"
        << "\n\t\t /indirect : Indirect Syscalls Detection"
		<< "\n\t\t /ssn : SSNcrushing"
        << "\n\t\t /help : Shows this help message and quits"
		<< "\n\n" << std::endl;
}

/**
   * Caramelle
*/
std::string caramelle() {
	return R"(
	  __      _
	o'')}____//
	 `_/      )
	 (_(_/-(_/
	)";
}