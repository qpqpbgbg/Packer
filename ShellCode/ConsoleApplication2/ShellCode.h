#pragma once
#include <windows.h>
#include <compressapi.h>
enum 
{
    //�ս�����
    SPACE_SECTION, 
    //���������
    CODE_SECTION,  
    //ѹ�����ݽ�����ֵ
    DATA_SECTION  
};

//ExitProcess
typedef
BOOL
(WINAPI* PFN_ExitProcess)(
    UINT uExitCode
    );

//C�⺯��Դ��
int __cdecl mymemcmp(
    const void * buf1,
    const void * buf2,
    size_t count
    );

void * __cdecl mymemset(
    void *dst,
    int val,
    size_t count
    );

void * __cdecl mymemcpy(
    void * dst,
    const void * src,
    size_t count
    );

//LoadLibraryA
typedef
HMODULE
(WINAPI* PFN_LoadLibraryA)(
    _In_ LPCSTR lpLibFileName
    );

//CreateDecompressor
typedef
BOOL
(WINAPI* PFN_CreateDecompressor)(
    _In_ DWORD Algorithm,
    _In_opt_ PCOMPRESS_ALLOCATION_ROUTINES AllocationRoutines,
    _Out_ PDECOMPRESSOR_HANDLE DecompressorHandle
    );

//Decompress
typedef
BOOL
(WINAPI* PFN_Decompress)(
    _In_ DECOMPRESSOR_HANDLE DecompressorHandle,
    _In_reads_bytes_opt_(CompressedDataSize) PVOID CompressedData,
    _In_ SIZE_T CompressedDataSize,
    _Out_writes_bytes_opt_(UncompressedBufferSize) PVOID UncompressedBuffer,
    _In_ SIZE_T UncompressedBufferSize,
    _Out_opt_ PSIZE_T UncompressedDataSize
    );

//VirtualAlloc
typedef
LPVOID
(WINAPI* PFN_VirtualAlloc)(
    _In_opt_ LPVOID lpAddress,
    _In_ SIZE_T dwSize,
    _In_ DWORD flAllocationType,
    _In_ DWORD flProtect
    );

//VirtualProtect
typedef
BOOL
(WINAPI* PFN_VirtualProtect)(
    _In_ LPVOID lpAddress,
    _In_ SIZE_T dwSize,
    _In_ DWORD flNewProtect,
    _Out_ PDWORD lpflOldProtect
    );


typedef struct tagEnvironment
{
    PFN_LoadLibraryA pfnLoadLibrary = NULL;
    PFN_CreateDecompressor pfnCreateDecompressor = NULL;
    PFN_Decompress pfnDecompress = NULL;
    PFN_VirtualAlloc pfnVirtualAlloc = NULL;
    PFN_VirtualProtect pfnVirtualProtect = NULL;
    PFN_ExitProcess pfnExitProcess = NULL;
}ENVIRONMENT, *PENVIRONMENT;

//��ʼ�����ֺ���ָ��
void InitFunPtr(PENVIRONMENT FunPtr);
//��ȡģ����
HMODULE MyGetModuleHandle(LPCTSTR modulename);
//��ȡ����������ַ
FARPROC MyGetProAddress(HMODULE hModule, LPCSTR lpProcName);
//loadpe
BOOL LoadPe(PENVIRONMENT FunPtr, void *PeFile);
//��λѹ��������
BOOL FindCompressData(LPBYTE &CompressDataBuf, ULONG *CompressBeforeSize, ULONG *SrcSize);
//��ѹ������
BOOL UnPackCompressData(
    PENVIRONMENT FunPtr,        //�ú���ָ��
    LPBYTE CompressDataBuff,    //ѹ�����ݵĻ�����
    ULONG ComopressSize,        //ѹ�����ݵĴ�С
    ULONG UnCompressSize,       //��ѹ�������ݵĴ�С
    LPBYTE *UnComressDataBuff   //��ѹ�����������ڵĻ�����
    );
//������
void IsDebug(PENVIRONMENT Funptr);

