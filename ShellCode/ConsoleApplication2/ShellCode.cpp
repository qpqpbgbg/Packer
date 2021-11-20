#pragma once
#include "ShellCode.h"

//��λѹ��������
BOOL FindCompressData(LPBYTE &CompressDataBuf, ULONG *CompressBeforeSize, ULONG *SrcSize)
{
    //��ģ���ַ
    HMODULE hModBase = MyGetModuleHandle(NULL);
    //��dosͷ
    IMAGE_DOS_HEADER *DosHead = (PIMAGE_DOS_HEADER)hModBase;
    //��NTͷ
    IMAGE_NT_HEADERS *NtHead = (PIMAGE_NT_HEADERS)((LPBYTE)hModBase + DosHead->e_lfanew);
    //�ýڱ�
    IMAGE_SECTION_HEADER *SectionHead = (PIMAGE_SECTION_HEADER)((LPBYTE)&NtHead->OptionalHeader + NtHead->FileHeader.SizeOfOptionalHeader);

    //��ѹ�����ݵ�ַ
    CompressDataBuf = (LPBYTE)hModBase + SectionHead[DATA_SECTION].VirtualAddress;
    //ѹ�������ݴ�С
    *CompressBeforeSize = SectionHead[DATA_SECTION].PointerToRelocations;
    //��ѹ�����ݴ�С
    *SrcSize = SectionHead[DATA_SECTION].PointerToLinenumbers;
    return TRUE;
}

//��ѹ��
BOOL UnPackCompressData(
    PENVIRONMENT FunPtr,          //�ú���ָ��
    LPBYTE CompressDataBuff,    //ѹ�����ݵĻ�����
    ULONG ComopressSize,        //ѹ�����ݵĴ�С
    ULONG UnCompressSize,       //��ѹ�������ݵĴ�С
    LPBYTE *UnComressDataBuff //��ѹ�����������ڵĻ�����
    )
{
    DECOMPRESSOR_HANDLE hDecompressor;
    BOOL bSuccess = FunPtr->pfnCreateDecompressor(
        COMPRESS_ALGORITHM_XPRESS_HUFF, //  Compression Algorithm
        NULL,                           //  Optional allocation routine
        &hDecompressor);                 //  Handle

    *UnComressDataBuff = (LPBYTE)FunPtr->pfnVirtualAlloc(
        NULL,
        UnCompressSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    DWORD dwDecompressedDataSize = 0;
    bSuccess = FunPtr->pfnDecompress(
        hDecompressor,               //  Decompressor handle
        CompressDataBuff,           //  Compressed data
        ComopressSize,              //  Compressed data size
        *UnComressDataBuff,         //  Decompressed buffer
        UnCompressSize,     //  Decompressed buffer size
        &dwDecompressedDataSize);     //  Decompressed data size
    return TRUE;
}

void InitFunPtr(PENVIRONMENT FunPtr)
{
    char szLoadLibrary[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', '\0' };
    char szKernel32[] = { 'K', 'e', 'r', 'n', 'e', 'l', '3', '2','.', 'd', 'l', 'l', '\0' };
    char szVirtualAlloc[] = { 'V','i','r','t','u','a','l','A','l','l','o','c','\0' };
    char szVirtualProtect[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t','\0' };
    char szCabinet[] = { 'C','a','b','i','n','e','t','.','d','l','l','\0' };
    char szCreateDecompressor[] = { 'C','r','e','a','t','e','D','e','c','o','m','p','r','e','s','s','o','r','\0' };
    char szDecompress[] = { 'D','e','c','o','m','p','r','e','s','s','\0' };
    char szExitProcess[] = { 'E','x','i','t','P','r','o','c','e','s','s','\0' };

    //��kernel32ģ��
    HMODULE hKernel32 = MyGetModuleHandle(szKernel32);
    //��szCabinetģ��
    FunPtr->pfnLoadLibrary = (PFN_LoadLibraryA)MyGetProAddress(hKernel32, szLoadLibrary);
    HMODULE hCabinet = FunPtr->pfnLoadLibrary(szCabinet);
    //�ø��ֺ�����ַ
    FunPtr->pfnVirtualAlloc = (PFN_VirtualAlloc)MyGetProAddress(hKernel32, szVirtualAlloc);
    FunPtr->pfnVirtualProtect = (PFN_VirtualProtect)MyGetProAddress(hKernel32, szVirtualProtect);
    FunPtr->pfnCreateDecompressor = (PFN_CreateDecompressor)MyGetProAddress(hCabinet, szCreateDecompressor);
    FunPtr->pfnDecompress = (PFN_Decompress)MyGetProAddress(hCabinet, szDecompress);
    FunPtr->pfnExitProcess = (PFN_ExitProcess)MyGetProAddress(hKernel32, szExitProcess);
}

//��ʵ��C�⺯��
int __cdecl mymemcmp(
    const void * buf1,
    const void * buf2,
    size_t count
    )
{
    if (!count)
        return(0);

    while (--count && *(char *)buf1 == *(char *)buf2)
    {
        buf1 = (char *)buf1 + 1;
        buf2 = (char *)buf2 + 1;
    }

    return(*((unsigned char *)buf1) - *((unsigned char *)buf2));
}


void * __cdecl mymemset(
    void *dst,
    int val,
    size_t count
    )
{
    void *start = dst;

    while (count--)
    {
        *(char *)dst = (char)val;
        dst = (char *)dst + 1;
    }

    return(start);
}

void * __cdecl mymemcpy(
    void * dst,
    const void * src,
    size_t count
    )
{
    void * ret = dst;

    /*
    * copy from lower addresses to higher addresses
    */
    while (count--)
    {
        *(char *)dst = *(char *)src;
        dst = (char *)dst + 1;
        src = (char *)src + 1;
    }

    return(ret);
}

//��ģ�鵼���ĺ�����ַ
FARPROC MyGetProAddress(HMODULE hModule, LPCSTR lpProcName)
{
    //1.��λ������
    IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)hModule;
    IMAGE_NT_HEADERS* NtHeader = (IMAGE_NT_HEADERS *)((char*)hModule + DosHeader->e_lfanew);

    IMAGE_EXPORT_DIRECTORY* ExportTable = (IMAGE_EXPORT_DIRECTORY*)((char*)NtHeader->OptionalHeader.DataDirectory[0].VirtualAddress + (DWORD)hModule);
    //2.ȡ����Ҫ����
    DWORD dwBase = ExportTable->Base;
    DWORD dwNumberOfFunctions = ExportTable->NumberOfFunctions; 
    DWORD dwNumberOfNames = ExportTable->NumberOfNames;
    //������ַ��
    DWORD dwAddressOfFunctions = ExportTable->AddressOfFunctions;
    //�������Ʊ�
    DWORD dwAddressOfNames = ExportTable->AddressOfNames;
    //������ű�
    DWORD dwAddressOfNameOrdinals = ExportTable->AddressOfNameOrdinals;
    dwAddressOfFunctions += (DWORD)hModule;
    dwAddressOfNames += (DWORD)hModule;
    dwAddressOfNameOrdinals += (DWORD)hModule;
    //3.���daochu
    DWORD dwIndex = 0;
    if ((DWORD)lpProcName <= 0x0ffff)
    {
        dwIndex = (DWORD)lpProcName - dwBase;
        if (dwIndex > dwNumberOfFunctions)
        {
            return NULL;
        }
    }
    //4.���Ƶ���
    else	
    {
        //���������ַ�������
        DWORD dwProcNameLength = 0;
        for (int i = 0; ; i++)
        {
            if (lpProcName[i] == 0x0)
            {
                break;
            }
            dwProcNameLength++;
        }
        BOOL bFlag = FALSE;
        for (ULONG i = 0; i < dwNumberOfNames; i++)
        {
            if (bFlag == TRUE)
            {
                break;
            }
            DWORD lpNameAddress = dwAddressOfNames + (i * sizeof(DWORD));
            char* szCurrentProcName = (char*)* (DWORD*)lpNameAddress;
            szCurrentProcName += (DWORD)hModule;
            //ѭ���Ƚ��ַ����Ƿ����

            DWORD dwCurrentLengt = 0;
            //�����ǰ����������
            for (int i = 0;; i++)
            {

                if (szCurrentProcName[i] == 0x0)
                {
                    break;
                }
                dwCurrentLengt++;
            }

            //�������
            if (dwCurrentLengt == dwProcNameLength)
            {
                for (ULONG j = 0; j < dwCurrentLengt; j++)
                {
                    if (szCurrentProcName[j] != lpProcName[j])
                    {
                        break;
                    }
                    //��ѯ���˺�����
                    if ((szCurrentProcName[j] == lpProcName[j]) && j == dwCurrentLengt - 1)
                    {
                        //ȡ����Ӧ�����
                        dwIndex = *(WORD*)(dwAddressOfNameOrdinals + sizeof(WORD)*i);
                        bFlag = TRUE;
                    }
                }
            }
            //δ��ѯ��
            if (i == (dwNumberOfNames - 1) && bFlag == FALSE)
            {
                return NULL;
            }
        }
    }
    dwAddressOfFunctions += (sizeof(DWORD) * dwIndex);
    DWORD dwQueryAddress = (DWORD)((char*)(*(DWORD*)dwAddressOfFunctions) + (DWORD)hModule);
    return (FARPROC)dwQueryAddress;
}

//ͨ�����ֻ��ģ����
HMODULE MyGetModuleHandle(LPCTSTR modulename)
{
    HMODULE hret = NULL;
    //�ж�����������������Ϊ��,�Ǿ�ֱ�ӻ���Լ��ģ������������������������
    if (modulename == NULL)
    {
        __asm
        {
            //��ȡ��ָ�����selfָ��
            mov eax, dword ptr fs : [0x18]
            //���PEB(���̻�����)ָ��
            mov eax, dword ptr[eax + 0x30]
            //���ImageBase
            mov eax, dword ptr[eax + 0x8]
            mov hret, eax
        }
    }
    //���Ҫ������ģ�飬������������,ASCIIת��UNICODE
    else
    {
        //���������ַ
        DWORD plst = NULL;
        //����������ʼ��ַ
        DWORD plstbegin = NULL;
        //����������һ����ַ
        DWORD pnextlst = NULL;
        //��ǰ������
        DWORD pcurrentlst = NULL;
        //Ҫ�Ƚϵ��ַ�����ַ
        DWORD pdstname = NULL;
        //Ҫ�Ƚϵ��ַ����ĳ���
        DWORD pdstnamelen = NULL;
        //Դ�ַ���������
        char srcnamebuf[MAX_PATH];
        //ȡ��UNIDOE��ת��ASCII���Ļ�����
        char dstnamebuf[MAX_PATH];
        //�Ƿ�ģ������ͬ�ı�ʶ
        BOOL ismodule = FALSE;

        //��������ʼ��Ϊ0
        for (int i = 0; i < MAX_PATH; ++i)
        {
            srcnamebuf[i] = 0;
            dstnamebuf[i] = 0;
        }

        //������дͳһСд,��д��ĸASCII��32 A+32 = a
        for (int i = 0; i < modulename[i] != '\0'; i++)
        {
            srcnamebuf[i] = modulename[i];
            if (srcnamebuf[i] >= 'A'&& srcnamebuf[i] <= 'Z')
            {
                srcnamebuf[i] += 32;
            }
        }

        //����û�����Ϣ
        __asm
        {
            //��ȡ��ָ�����selfָ��
            mov eax, dword ptr fs : [0x18]
            //���PEB(���̻�����)ָ��
            mov eax, dword ptr[eax + 0x30]
            //���װ��ģ��LDR��Ϣ
            mov eax, dword ptr[eax + 0xc]
            //��û������� 
            mov eax, dword ptr[eax + 0xc]   
            //���滷������
            mov plst, eax
            //����ͷ���
            mov plstbegin, eax
            //���浱ǰ�ģ�����ʹ��
            mov pcurrentlst, eax
        }
        //ѭ������������ͬ��ƥ����
        while (1)
        {
            //ָ��ָ��ģ��������ȡ��size�ͳ��� ��16λsize ��16λlen
            pdstnamelen = *((int*)(pcurrentlst + 0x2c));
            //�������
            pdstnamelen = pdstnamelen & 0x0000ffff;
            //���ָ��Ŀ����ַ�����ַ
            pdstname = *((int*)(pcurrentlst + 0x30));

            //UNICODEתASCII                                        
            for (ULONG i = 0; i < pdstnamelen; i++)
            {
                dstnamebuf[i / 2] = *((char*)(pdstname + i));
                //����forѭ���ģ�ÿ���±�+2
                i++;
            }

            //Ŀ���ַ�����дתСд
            for (int i = 0; dstnamebuf[i] != '\0'; i++)
            {
                if (dstnamebuf[i] >= 'A' && dstnamebuf[i] <= 'Z')
                {
                    dstnamebuf[i] += 32;
                }
            }

            //��Ŀ���ַ�������Ϊ׼,����Դ�ַ���ѭ���жϽ���
            for (int i = 0; dstnamebuf[i] != '\0'; i++)
            {
                if (srcnamebuf[i] != dstnamebuf[i])
                {
                    ismodule = FALSE;
                    break;
                }
                //Ҫ��ѯ�����Ʋ�����Ŀ������
                if (srcnamebuf[i] == '\0' && dstnamebuf[i] != '\0')
                {
                    ismodule = FALSE;
                    break;
                }
                ismodule = TRUE;
            }
            //Ҫ���ҵ��ַ�����ȫ��ͬ
            if (ismodule == TRUE)
            {
                hret = (HMODULE)*((int*)(pcurrentlst + 0x18));
                break;
            }

            //��������һ��֮ǰ����ձ��ε�Ŀ��Ƚ��ַ���������
            for (int i = 0; dstnamebuf[i] != '\0'; i++)
            {
                dstnamebuf[i] = '\0';
            }

            //�������һȦ,�˳�ѭ��
            if (pnextlst == plstbegin)
            {
                break;
            }
            pnextlst = *((int*)(pcurrentlst));
            pcurrentlst = pnextlst;
        }

    }
    return hret;
}

BOOL LoadPe(PENVIRONMENT pEnv, void* PeFile)
{
    IMAGE_DOS_HEADER* lpDosHead = (IMAGE_DOS_HEADER*)PeFile;
    IMAGE_NT_HEADERS* lpNtHead = (IMAGE_NT_HEADERS*)((char*)PeFile + lpDosHead->e_lfanew);
    IMAGE_FILE_HEADER* lpFileHead = &lpNtHead->FileHeader;//�ļ�ͷ��ַ
    IMAGE_OPTIONAL_HEADER32* lpOptionalHeader = &lpNtHead->OptionalHeader;//��ѡͷ��ַ
    IMAGE_DATA_DIRECTORY* lpDirectory = lpOptionalHeader->DataDirectory;//����Ŀ¼��ַ

    DWORD lpImportTable = lpOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    DWORD dwSizeofSection = lpFileHead->NumberOfSections;//�ڱ�����
    DWORD dwSizeOfOptional = lpFileHead->SizeOfOptionalHeader;//��ѡͷ��С
    IMAGE_SECTION_HEADER* lpSection = (IMAGE_SECTION_HEADER*)((char*)lpOptionalHeader + dwSizeOfOptional);//�ڱ��׵�ַ

    DWORD dwSizeOfImage = lpOptionalHeader->SizeOfImage;
    DWORD dwImageBase = lpOptionalHeader->ImageBase;//ӳ���ַ
    lpImportTable += dwImageBase;//������ַ
    DWORD dwAddressOfEntryPoint = lpOptionalHeader->AddressOfEntryPoint;//������ڵ�
    dwAddressOfEntryPoint += dwImageBase;
    DWORD dwSizeOfHead = lpOptionalHeader->SizeOfHeaders;
    DWORD dwOldProtect = 0;
    if (pEnv->pfnVirtualProtect((VOID*)dwImageBase, dwSizeOfImage, PAGE_EXECUTE_READWRITE, &dwOldProtect) == 0)
    {
        return false;
    }

    //����ͷ��
    mymemcpy((void*)dwImageBase, PeFile, dwSizeOfHead);
    //�����ڱ�
    for (ULONG i = 0; i < dwSizeofSection; i++)
    {
        //�����ڴ�ڱ���ʼ��ַ
        DWORD dwVirAddress = lpSection->VirtualAddress;
        dwVirAddress += dwImageBase;
        //�ļ�ƫ��
        DWORD dwFileOffset = lpSection->PointerToRawData;
        //��С
        DWORD dwSizeOfSection = lpSection->SizeOfRawData;
        //����������
        mymemcpy((void*)dwVirAddress, ((char*)PeFile + dwFileOffset), dwSizeOfSection);
        lpSection++;
    }

    //����IAT
    IMAGE_IMPORT_DESCRIPTOR  ZeroImport;
    mymemset(&ZeroImport, 0, sizeof(ZeroImport));
    while (mymemcmp(&ZeroImport, (void*)lpImportTable, sizeof(IMAGE_IMPORT_DESCRIPTOR)) != 0)
    {
        IMAGE_IMPORT_DESCRIPTOR* lpCuurentImport = (IMAGE_IMPORT_DESCRIPTOR*)lpImportTable;
        lpImportTable += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        //����
        DWORD lpIat = lpCuurentImport->FirstThunk;
        lpIat += dwImageBase;
        //����Ƿ�����Чpe
        if (*(DWORD*)lpIat == 0)   
        {
            continue;

        }
        DWORD lpInt = lpCuurentImport->OriginalFirstThunk;
        if (lpInt == NULL)
        {
            lpInt = lpCuurentImport->FirstThunk;
        }
        //����INT
        lpInt += dwImageBase;
        //��Ч��
        if (lpInt == NULL)
        {
            return FALSE;
        }
        DWORD lpDllName = lpCuurentImport->Name;
        lpDllName += dwImageBase;
        HMODULE hModule = pEnv->pfnLoadLibrary((char*)lpDllName);
        if (hModule == NULL)
        {
            return FALSE;
        }
        int i = 0;
        DWORD lpFun = 0;
        while (*(DWORD*)lpInt != 0)
        {
            //�ַ�������
            if (((*(DWORD*)lpInt) & 0x80000000) == 0)
            {
                lpFun = (DWORD)((char*)(*(DWORD*)lpInt) + dwImageBase + 2);
            }
            //��ŵ���
            else 
            {
                lpFun = *(DWORD*)lpInt & 0x0ffff;
            }

            DWORD lpPfnAddress = (DWORD)MyGetProAddress(hModule, (char*)lpFun);
            if (lpPfnAddress == NULL)
            {
                return FALSE;
            }
            *((DWORD*)lpIat + i) = lpPfnAddress;
            i++;
            lpInt = (DWORD)((DWORD*)lpInt + 1);
        }

    }
    IsDebug(pEnv);
    __asm
    {
        jmp dwAddressOfEntryPoint;
    }
    return TRUE;
}

void IsDebug(PENVIRONMENT Funptr)
{
    //����û�����Ϣ
    ULONG BeingDebugged = 0;
    ULONG NtGlobalFlag = 0;
    //ȡBeingDebugged
    __asm
    {
        push edx;
        push eax;
        mov eax, dword ptr fs : [0x18];
        mov eax, dword ptr ds:[eax + 0x30];
        movzx edx, dword ptr ds : [eax + 0x68];
        movzx eax, dword ptr ds:[eax + 0x2];
        mov NtGlobalFlag, edx;
        mov BeingDebugged, eax;
        pop eax;
        pop edx;
    }
    if (BeingDebugged != 0 || NtGlobalFlag == 0x70)
    {
        Funptr->pfnExitProcess(BeingDebugged);
    }
}