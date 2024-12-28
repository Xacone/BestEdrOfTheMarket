#include "Globals.h"

ULONG HashFunction(PVOID Address) {
    return ((ULONG_PTR)Address) % HASH_TABLE_SIZE;
}

VOID InitializeFunctionMap(PFUNCTION_MAP Map) {
    RtlZeroMemory(Map, sizeof(FUNCTION_MAP));
}

VOID AddFunctionToMap(PFUNCTION_MAP Map, PVOID Address, PUNICODE_STRING FunctionName) {

    ULONG hashIndex = HashFunction(Address);
    PFUNCTION_NODE newNode = (PFUNCTION_NODE)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(FUNCTION_NODE), 'tnF');
    if (newNode == NULL) {
        DbgPrint("Failed to allocate memory for FUNCTION_NODE\n");
        return;
    }

    newNode->Address = Address;
    RtlInitUnicodeString(&newNode->FunctionName, NULL);
    RtlDuplicateUnicodeString(RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE, FunctionName, &newNode->FunctionName);
    newNode->Next = Map->Buckets[hashIndex];
    Map->Buckets[hashIndex] = newNode;
}

UNICODE_STRING* GetFunctionNameFromMap(PFUNCTION_MAP Map, PVOID Address, KMUTEX* funcMapMutex, BOOLEAN mutInit) {

    if (!mutInit) {
        return NULL;
    }

    KeWaitForSingleObject(funcMapMutex, Executive, KernelMode, FALSE, NULL);

    ULONG hashIndex = HashFunction(Address);
    PFUNCTION_NODE current = Map->Buckets[hashIndex];

    while (current) {
        if (MmIsAddressValid(current) == FALSE) {
            DbgPrint("[-] Invalid PFUNCTION_NODE at %p\n", current);
            break;
        }
        if (current->Address == Address) {
            KeReleaseMutex(funcMapMutex, FALSE);
            return &current->FunctionName;
        }
        current = current->Next;
    }

    KeReleaseMutex(funcMapMutex, FALSE);
    return NULL;
}

UNICODE_STRING* GetFunctionNameFromMap(PFUNCTION_MAP Map, PVOID Address) {

    ULONG hashIndex = HashFunction(Address);
    PFUNCTION_NODE current = Map->Buckets[hashIndex];

    while (current) {
        if (MmIsAddressValid(current) == FALSE) {
            DbgPrint("[-] Invalid PFUNCTION_NODE at %p\n", current);
            break;
        }
        if (current->Address == Address) {
            return &current->FunctionName;
        }
        current = current->Next;
    }
	return NULL;
}

VOID FreeFunctionMap(PFUNCTION_MAP Map) {
    for (ULONG i = 0; i < HASH_TABLE_SIZE; i++) {
        PFUNCTION_NODE current = Map->Buckets[i];
        while (current) {
            PFUNCTION_NODE temp = current;
            current = current->Next;

            if (temp->FunctionName.Buffer) {
                RtlFreeUnicodeString(&temp->FunctionName);
            }
            ExFreePool(temp);
        }
    }
}
