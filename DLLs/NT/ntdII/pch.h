#ifndef PCH_H
#define PCH_H

#include "framework.h"
#include <winternl.h>

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

#ifndef _CLIENT_ID_DEFINED_
#define _CLIENT_ID_DEFINED_

typedef struct _CLIENT_ID_
{
    PVOID UniqueProcess;
    PVOID UniqueThread;
} *_PCLIENT_ID_;

#endif // _CLIENT_ID_DEFINED_

typedef struct _CURDIR
{
    UNICODE_STRING DosPath;
    PVOID Handle;
} CURDIR, * PCURDIR;

typedef struct _INITIAL_TEB {
    PVOID                StackBase;
    PVOID                StackLimit;
    PVOID                StackCommit;
    PVOID                StackCommitMax;
    PVOID                StackReserved;
} INITIAL_TEB, * PINITIAL_TEB;


typedef struct _RTL_DRIVE_LETTER_CURDIR {
    USHORT                  Flags;
    USHORT                  Length;
    ULONG                   TimeStamp;
    UNICODE_STRING          DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;



#endif //PCH_H
