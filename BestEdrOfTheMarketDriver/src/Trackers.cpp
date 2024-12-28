#include "Globals.h"

void ThreadTracker::InitializeThreadTracker() {

    DbgPrint("[+] Initializing Thread Tracker\n");

    InitializeListHead(&g_ThreadTracker.Head);
    KeInitializeSpinLock(&g_ThreadTracker.Lock);
}

void ThreadTracker::AddThread(HANDLE ProcessId, HANDLE ThreadId) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_ThreadTracker.Lock, &oldIrql);

    PTHREAD_TRACKER_ENTRY entry = (PTHREAD_TRACKER_ENTRY)ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_RAISE_ON_FAILURE, sizeof(THREAD_TRACKER_ENTRY), 'pdzM');
    if (entry) {
        entry->ProcessId = ProcessId;
        entry->ThreadId = ThreadId;
        entry->IsCreated = TRUE;
        InsertTailList(&g_ThreadTracker.Head, &entry->ListEntry);
    }
    else {
        DbgPrint("[-] Failed to allocate memory for thread entry\n");
    }

    KeReleaseSpinLock(&g_ThreadTracker.Lock, oldIrql);
}

void ThreadTracker::RemoveThread(HANDLE ThreadId) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_ThreadTracker.Lock, &oldIrql);

    PLIST_ENTRY listEntry = g_ThreadTracker.Head.Flink;
    while (listEntry != &g_ThreadTracker.Head) {
        PTHREAD_TRACKER_ENTRY entry = CONTAINING_RECORD(listEntry, THREAD_TRACKER_ENTRY, ListEntry);
        if (entry->ThreadId == ThreadId) {
            RemoveEntryList(listEntry);
            ExFreePool(entry);            
            break;
        }
        listEntry = listEntry->Flink;
    }

    KeReleaseSpinLock(&g_ThreadTracker.Lock, oldIrql);
}
