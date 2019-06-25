#include "ntos.h"

// type definitions
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
	NTSTATUS Status = STATUS_FAIL_CHECK;

	// lookup eprocess for use in attaching
	if (!NT_SUCCESS(PsLookupProcessByProcessId((PVOID)PID, &Process)))
		return STATUS_INVALID_PARAMETER_1;

	// create our own variables for usermode buffer, for some reason it will crash if we dont use these variables
	PVOID Address = (PVOID)sent->read.Address;
	SIZE_T Size = sent->read.Size;

	// alocate memory for our driverbuffer, will be used to read memory from the process
	PVOID* Buffer = (PVOID*)ExAllocatePool(NonPagedPool, Size); // Pointer to Allocated Memory
	if (Buffer == NULL)
		return STATUS_MEMORY_NOT_ALLOCATED;

	*Buffer = (PVOID)1;

	__try {
		// attach
		KeStackAttachProcess(Process, &APC);

		// verify address is valid before doing anything else
		if (!MmIsAddressValid(Address)) {
			KeUnstackDetachProcess(&APC);

			ExFreePool(Buffer);
			ObfDereferenceObject(Process);

			Status = STATUS_INVALID_ADDRESS;

			return Status;
		}

		// query information on memory to verify it meets our requirements
		MEMORY_BASIC_INFORMATION info;
		if (!NT_SUCCESS(ZwQueryVirtualMemory(ZwCurrentProcess(), Address, MemoryBasicInformation, &info, sizeof(MEMORY_BASIC_INFORMATION), NULL))) {
			KeUnstackDetachProcess(&APC);

			ExFreePool(Buffer);
			ObfDereferenceObject(Process);

			Status = STATUS_INVALID_ADDRESS_COMPONENT;

			return Status;
		}

		// secure memory so it doesnt change between the beginning of the request & the end, practically the same as doing ZwProtectVirtualMemory
		HANDLE Secure = MmSecureVirtualMemory(Address, Size, PAGE_READWRITE);
		if (Secure == NULL) {
			KeUnstackDetachProcess(&APC);

			ExFreePool(Buffer);
			ObfDereferenceObject(Process);

			Status = STATUS_ACCESS_VIOLATION;

			return Status;
		}

		ULONG flags = PAGE_EXECUTE_READWRITE | PAGE_READWRITE;
		ULONG page = PAGE_GUARD | PAGE_NOACCESS;

		// confirm memory block meets our requirements
		if (!(info.State & MEM_COMMIT) || !(info.Protect & flags) || (info.Protect & page)) {
			MmUnsecureVirtualMemory(Secure);
			KeUnstackDetachProcess(&APC);

			ExFreePool(Buffer);
			ObfDereferenceObject(Process);

			Status = STATUS_ACCESS_DENIED;

			return Status;
		}

		// read memory to our driver's buffer
		memcpy(Buffer, Address, Size);

		// cleanup, unsecure memory & detach from process
		MmUnsecureVirtualMemory(Secure);
		KeUnstackDetachProcess(&APC);

		// read memory from our driver's buffer over to our usermode buffer
		memcpy(sent->read.Response, Buffer, Size);

		Status = STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		// detach if anything goes wrong
		KeUnstackDetachProcess(&APC);
	}

	// cleanup for us, deallocate buffer memory & deref eprocess as we added a ref
	ExFreePool(Buffer);
	ObfDereferenceObject(Process);

	return Status;
}

NTSTATUS WVM(ULONG PID, MEMORY_REQUEST* sent) {
	PEPROCESS Process;
	KAPC_STATE APC;
	NTSTATUS Status;

	if (!NT_SUCCESS(PsLookupProcessByProcessId((PVOID)PID, &Process)))
		return STATUS_INVALID_PARAMETER_1;

	PVOID Address = (PVOID)sent->write.Address;
	SIZE_T Size = sent->write.Size;

	// allocate memory for our driver buffer
	PVOID* Buffer = (PVOID*)ExAllocatePool(NonPagedPool, Size); // Pointer to Allocated Memory
	if (Buffer == NULL)
		return STATUS_MEMORY_NOT_ALLOCATED;

	__try {
		// copy our usermode buffer's value over to our driver's buffer
		memcpy(Buffer, sent->write.Value, Size);

		KeStackAttachProcess(Process, &APC);

		if (!MmIsAddressValid(Address)) {
			KeUnstackDetachProcess(&APC);

			ExFreePool(Buffer);
			ObfDereferenceObject(Process);

			Status = STATUS_INVALID_ADDRESS;

			return Status;
		}

		MEMORY_BASIC_INFORMATION info;
		if (!NT_SUCCESS(ZwQueryVirtualMemory(ZwCurrentProcess(), Address, MemoryBasicInformation, &info, sizeof(MEMORY_BASIC_INFORMATION), NULL))) {
			KeUnstackDetachProcess(&APC);

			ExFreePool(Buffer);
			ObfDereferenceObject(Process);

			Status = STATUS_INVALID_PARAMETER_2;

			return Status;
		}

		HANDLE Secure = MmSecureVirtualMemory(Address, Size, PAGE_READWRITE);
		if (Secure == NULL) {
			KeUnstackDetachProcess(&APC);

			ExFreePool(Buffer);
			ObfDereferenceObject(Process);

			Status = STATUS_ACCESS_VIOLATION;

			return Status;
		}

		ULONG flags = PAGE_EXECUTE_READWRITE | PAGE_READWRITE;
		ULONG page = PAGE_GUARD | PAGE_NOACCESS;

		if (!(info.State & MEM_COMMIT) || !(info.Protect & flags) || (info.Protect & page)) {
			MmUnsecureVirtualMemory(Secure);
			KeUnstackDetachProcess(&APC);

			ExFreePool(Buffer);
			ObfDereferenceObject(Process);

			Status = STATUS_ACCESS_DENIED;

			return Status;
		}

		// send our driver's buffer to our applications memory address
		memcpy(Address, Buffer, Size);

		MmUnsecureVirtualMemory(Secure);
		KeUnstackDetachProcess(&APC);

		Status = STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		KeUnstackDetachProcess(&APC);
	}

	ExFreePool(Buffer);
	ObfDereferenceObject(Process);

	return Status;
}

DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	UNREFERENCED_PARAMETER(pDriverObject);
	UNREFERENCED_PARAMETER(pRegistryPath);

	return STATUS_SUCCESS;
}
