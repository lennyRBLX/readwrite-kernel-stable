#include "ntos.h"

typedef unsigned long long QWORD;
typedef unsigned short WORD;
typedef unsigned long DWORD, * PDWORD, * LPDWORD;

// credits to paracord, wjcsharp, & cheat-engine's repositories, without them I wouldn't of been able to figure out the puzzel of reading and writing with kernel mode buffers & user mode memory

/*

paracord - https://github.com/paracorded/read_write
wjcsharp - https://github.com/wjcsharp/wintools/blob/79b3883aacb5833d747d5bedce843086c327dff3/examples/random/ReadMemoryKernel.c
cheat-engine - https://github.com/cheat-engine/cheat-engine/blob/master/DBKKernel/memscan.c

*/

// structure definitions
typedef struct _KERNEL_READ_REQUEST
{
	UINT64 Address; // Source
	PVOID Response; // Target
	SIZE_T Size;
} KERNEL_READ_REQUEST, *PKERNEL_READ_REQUEST;

typedef struct _KERNEL_WRITE_REQUEST
{
	UINT64 Address; // Target
	PVOID Value; // Source
	SIZE_T Size;
} KERNEL_WRITE_REQUEST, *PKERNEL_WRITE_REQUEST;

typedef struct _MEMORY_REQUEST
{
	ULONG ProcessId;
	KERNEL_READ_REQUEST read;
	KERNEL_WRITE_REQUEST write;
} MEMORY_REQUEST;

// method definitions
NTSTATUS RVM(ULONG PID, MEMORY_REQUEST* sent) {
	PEPROCESS Process;
	KAPC_STATE APC;

	if (!NT_SUCCESS(PsLookupProcessByProcessId((PVOID)PID, &Process))) // gets PEPROCESS from PID
		return STATUS_INVALID_PARAMETER_1;

	// Gathers needed information from Usermode Buffer
	PVOID Address = (PVOID)sent->read.Address;
	SIZE_T Size = sent->read.Size;
	PVOID* Buffer = (PVOID*)ExAllocatePool(NonPagedPool, Size); // Pointer to Allocated Memory
	
	if (Buffer == NULL)
		return STATUS_MEMORY_NOT_ALLOCATED;
	
	*Buffer = (PVOID)1; // To ensure it isnt NULL

	KeStackAttachProcess(Process, &APC);

	// Secures Virtual Memory to ensure Query is correct throughout testing & writing
	HANDLE Secure = MmSecureVirtualMemory(Address, Size, PAGE_READWRITE);
	MEMORY_BASIC_INFORMATION info;

	// Gets information on Memory Block to ensure it is safe to Read / Write
	if (!NT_SUCCESS(ZwQueryVirtualMemory(ZwCurrentProcess(), Address, MemoryBasicInformation, &info, sizeof(MEMORY_BASIC_INFORMATION), NULL))) {
		MmUnsecureVirtualMemory(Secure);
		KeUnstackDetachProcess(&APC);

		return STATUS_INVALID_PARAMETER_2;
	}

	// My personal flags, all the flags are available @ https://docs.microsoft.com/en-us/windows/desktop/Memory/memory-protection-constants
	ULONG flags = PAGE_EXECUTE_READWRITE | PAGE_READWRITE;
	ULONG page = PAGE_GUARD | PAGE_NOACCESS;

	// Credits to Paracord for the if statement, this is basically copy & paste
	if (!(info.State & MEM_COMMIT) || !(info.Protect & flags) || (info.Protect & page)) {
		MmUnsecureVirtualMemory(Secure);
		KeUnstackDetachProcess(&APC);

		return STATUS_ACCESS_DENIED;
	}

	// Double check if the Address is even valid, the function is technically just a wrapper for a try catch exception handler on reading the memory block
	if (!MmIsAddressValid(Address)) {
		MmUnsecureVirtualMemory(Secure);
		KeUnstackDetachProcess(&APC);

		return STATUS_INVALID_ADDRESS;
	}

	// Copy memory from Process -> Our Buffer
	memcpy(Buffer, Address, Size);

	// Unsecure the secure handle so we don't cause issues in the Process later down the line, AKA Cleanup
	MmUnsecureVirtualMemory(Secure);
	KeUnstackDetachProcess(&APC);

	// Send Buffer value to Usermode
	memcpy(sent->read.Response, Buffer, Size);
	
	ExFreePool(Buffer); // Free Pool so there isnt a chance of Memory Leaks

	// We added a reference to the PEPROCESS so we must dereference it again to make sure it's reference count is even
	ObfDereferenceObject(Process);

	return STATUS_SUCCESS;
}

NTSTATUS WVM(ULONG PID, MEMORY_REQUEST* sent) {
	PEPROCESS Process;
	KAPC_STATE APC;

	if (!NT_SUCCESS(PsLookupProcessByProcessId((PVOID)PID, &Process)))
		return STATUS_INVALID_PARAMETER_1;

	PVOID Address = (PVOID)sent->write.Address;
	SIZE_T Size = sent->write.Size;
	PVOID* Buffer = (PVOID*)ExAllocatePool(NonPagedPool, Size); // Pointer to Allocated Memory
	
	if (Buffer == NULL)
		return STATUS_MEMORY_NOT_ALLOCATED;

	memcpy(Buffer, sent->write.Value, Size); // Copy Value over to Buffer so we can Write with Buffer

	KeStackAttachProcess(Process, &APC);

	HANDLE Secure = MmSecureVirtualMemory(Address, Size, PAGE_READWRITE);
	MEMORY_BASIC_INFORMATION info;

	if (!NT_SUCCESS(ZwQueryVirtualMemory(ZwCurrentProcess(), Address, MemoryBasicInformation, &info, sizeof(MEMORY_BASIC_INFORMATION), NULL))) {
		MmUnsecureVirtualMemory(Secure);
		KeUnstackDetachProcess(&APC);

		return STATUS_INVALID_PARAMETER_2;
	}

	ULONG flags = PAGE_EXECUTE_READWRITE | PAGE_READWRITE;
	ULONG page = PAGE_GUARD | PAGE_NOACCESS;

	if (!(info.State & MEM_COMMIT) || !(info.Protect & flags) || (info.Protect & page)) {
		MmUnsecureVirtualMemory(Secure);
		KeUnstackDetachProcess(&APC);

		return STATUS_ACCESS_DENIED;
	}

	if (!MmIsAddressValid(Address)) {
		MmUnsecureVirtualMemory(Secure);
		KeUnstackDetachProcess(&APC);

		return STATUS_INVALID_ADDRESS;
	}

	memcpy(Address, Buffer, Size); // Switch arguements around to Write, instead of Reading

	MmUnsecureVirtualMemory(Secure);
	KeUnstackDetachProcess(&APC);
	
	ExFreePool(Buffer);

	ObfDereferenceObject(Process);

	return STATUS_SUCCESS;
}

DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	UNREFERENCED_PARAMETER(pDriverObject);
	UNREFERENCED_PARAMETER(pRegistryPath);

	return STATUS_SUCCESS;
}
