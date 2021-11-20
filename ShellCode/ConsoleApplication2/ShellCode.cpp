#pragma once
#include "ShellCode.h"

//定位压缩的数据
BOOL FindCompressData(LPBYTE &CompressDataBuf, ULONG *CompressBeforeSize, ULONG *SrcSize)
{
    //拿模块地址
    HMODULE hModBase = MyGetModuleHandle(NULL);
    //拿dos头
    IMAGE_DOS_HEADER *DosHead = (PIMAGE_DOS_HEADER)hModBase;
    //拿NT头
    IMAGE_NT_HEADERS *NtHead = (PIMAGE_NT_HEADERS)((LPBYTE)hModBase + DosHead->e_lfanew);
    //拿节表
    IMAGE_SECTION_HEADER *SectionHead = (PIMAGE_SECTION_HEADER)((LPBYTE)&NtHead->OptionalHeader + NtHead->FileHeader.SizeOfOptionalHeader);

    //拿压缩数据地址
    CompressDataBuf = (LPBYTE)hModBase + SectionHead[DATA_SECTION].VirtualAddress;
    //压缩后数据大小
    *CompressBeforeSize = SectionHead[DATA_SECTION].PointerToRelocations;
    //解压后数据大小
    *SrcSize = SectionHead[DATA_SECTION].PointerToLinenumbers;
    return TRUE;
}

//解压缩
BOOL UnPackCompressData(
    PENVIRONMENT FunPtr,          //拿函数指针
    LPBYTE CompressDataBuff,    //压缩数据的缓冲区
    ULONG ComopressSize,        //压缩数据的大小
    ULONG UnCompressSize,       //解压缩后数据的大小
    LPBYTE *UnComressDataBuff //解压缩后数据所在的缓冲区
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

    //拿kernel32模块
    HMODULE hKernel32 = MyGetModuleHandle(szKernel32);
    //拿szCabinet模块
    FunPtr->pfnLoadLibrary = (PFN_LoadLibraryA)MyGetProAddress(hKernel32, szLoadLibrary);
    HMODULE hCabinet = FunPtr->pfnLoadLibrary(szCabinet);
    //拿各种函数地址
    FunPtr->pfnVirtualAlloc = (PFN_VirtualAlloc)MyGetProAddress(hKernel32, szVirtualAlloc);
    FunPtr->pfnVirtualProtect = (PFN_VirtualProtect)MyGetProAddress(hKernel32, szVirtualProtect);
    FunPtr->pfnCreateDecompressor = (PFN_CreateDecompressor)MyGetProAddress(hCabinet, szCreateDecompressor);
    FunPtr->pfnDecompress = (PFN_Decompress)MyGetProAddress(hCabinet, szDecompress);
    FunPtr->pfnExitProcess = (PFN_ExitProcess)MyGetProAddress(hKernel32, szExitProcess);
}

//自实现C库函数
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

//拿模块导出的函数地址
FARPROC MyGetProAddress(HMODULE hModule, LPCSTR lpProcName)
{
    //1.定位导出表
    IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)hModule;
    IMAGE_NT_HEADERS* NtHeader = (IMAGE_NT_HEADERS *)((char*)hModule + DosHeader->e_lfanew);

    IMAGE_EXPORT_DIRECTORY* ExportTable = (IMAGE_EXPORT_DIRECTORY*)((char*)NtHeader->OptionalHeader.DataDirectory[0].VirtualAddress + (DWORD)hModule);
    //2.取出重要数据
    DWORD dwBase = ExportTable->Base;
    DWORD dwNumberOfFunctions = ExportTable->NumberOfFunctions; 
    DWORD dwNumberOfNames = ExportTable->NumberOfNames;
    //导出地址表
    DWORD dwAddressOfFunctions = ExportTable->AddressOfFunctions;
    //导出名称表
    DWORD dwAddressOfNames = ExportTable->AddressOfNames;
    //导出序号表
    DWORD dwAddressOfNameOrdinals = ExportTable->AddressOfNameOrdinals;
    dwAddressOfFunctions += (DWORD)hModule;
    dwAddressOfNames += (DWORD)hModule;
    dwAddressOfNameOrdinals += (DWORD)hModule;
    //3.序号daochu
    DWORD dwIndex = 0;
    if ((DWORD)lpProcName <= 0x0ffff)
    {
        dwIndex = (DWORD)lpProcName - dwBase;
        if (dwIndex > dwNumberOfFunctions)
        {
            return NULL;
        }
    }
    //4.名称导出
    else	
    {
        //求出输入的字符串长度
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
            //循环比较字符串是否相等

            DWORD dwCurrentLengt = 0;
            //求出当前函数名长度
            for (int i = 0;; i++)
            {

                if (szCurrentProcName[i] == 0x0)
                {
                    break;
                }
                dwCurrentLengt++;
            }

            //长度相等
            if (dwCurrentLengt == dwProcNameLength)
            {
                for (ULONG j = 0; j < dwCurrentLengt; j++)
                {
                    if (szCurrentProcName[j] != lpProcName[j])
                    {
                        break;
                    }
                    //查询到了函数名
                    if ((szCurrentProcName[j] == lpProcName[j]) && j == dwCurrentLengt - 1)
                    {
                        //取出对应的序号
                        dwIndex = *(WORD*)(dwAddressOfNameOrdinals + sizeof(WORD)*i);
                        bFlag = TRUE;
                    }
                }
            }
            //未查询到
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

//通过名字获得模块句柄
HMODULE MyGetModuleHandle(LPCTSTR modulename)
{
    HMODULE hret = NULL;
    //判断两种情况，如果参数为空,那就直接获得自己的，无需遍历环形链表中其他的
    if (modulename == NULL)
    {
        __asm
        {
            //获取回指自身的self指针
            mov eax, dword ptr fs : [0x18]
            //获得PEB(进程环境块)指针
            mov eax, dword ptr[eax + 0x30]
            //获得ImageBase
            mov eax, dword ptr[eax + 0x8]
            mov hret, eax
        }
    }
    //如果要找其余模块，遍历环形链表,ASCII转成UNICODE
    else
    {
        //环形链表地址
        DWORD plst = NULL;
        //环形链表起始地址
        DWORD plstbegin = NULL;
        //环形链表下一个地址
        DWORD pnextlst = NULL;
        //当前遍历的
        DWORD pcurrentlst = NULL;
        //要比较的字符串地址
        DWORD pdstname = NULL;
        //要比较的字符串的长度
        DWORD pdstnamelen = NULL;
        //源字符串缓冲区
        char srcnamebuf[MAX_PATH];
        //取出UNIDOE串转成ASCII串的缓冲区
        char dstnamebuf[MAX_PATH];
        //是否模块名相同的标识
        BOOL ismodule = FALSE;

        //数据区初始化为0
        for (int i = 0; i < MAX_PATH; ++i)
        {
            srcnamebuf[i] = 0;
            dstnamebuf[i] = 0;
        }

        //参数大写统一小写,大写字母ASCII增32 A+32 = a
        for (int i = 0; i < modulename[i] != '\0'; i++)
        {
            srcnamebuf[i] = modulename[i];
            if (srcnamebuf[i] >= 'A'&& srcnamebuf[i] <= 'Z')
            {
                srcnamebuf[i] += 32;
            }
        }

        //汇编获得基本信息
        __asm
        {
            //获取回指自身的self指针
            mov eax, dword ptr fs : [0x18]
            //获得PEB(进程环境块)指针
            mov eax, dword ptr[eax + 0x30]
            //获得装载模块LDR信息
            mov eax, dword ptr[eax + 0xc]
            //获得环形链表 
            mov eax, dword ptr[eax + 0xc]   
            //保存环形链表
            mov plst, eax
            //保存头结点
            mov plstbegin, eax
            //保存当前的，遍历使用
            mov pcurrentlst, eax
        }
        //循环遍历名称相同的匹配项
        while (1)
        {
            //指针指向模块名区域取出size和长度 高16位size 低16位len
            pdstnamelen = *((int*)(pcurrentlst + 0x2c));
            //求出长度
            pdstnamelen = pdstnamelen & 0x0000ffff;
            //获得指向目标的字符串地址
            pdstname = *((int*)(pcurrentlst + 0x30));

            //UNICODE转ASCII                                        
            for (ULONG i = 0; i < pdstnamelen; i++)
            {
                dstnamebuf[i / 2] = *((char*)(pdstname + i));
                //算上for循环的，每次下标+2
                i++;
            }

            //目标字符串大写转小写
            for (int i = 0; dstnamebuf[i] != '\0'; i++)
            {
                if (dstnamebuf[i] >= 'A' && dstnamebuf[i] <= 'Z')
                {
                    dstnamebuf[i] += 32;
                }
            }

            //以目标字符串长度为准,并且源字符串循环判断结束
            for (int i = 0; dstnamebuf[i] != '\0'; i++)
            {
                if (srcnamebuf[i] != dstnamebuf[i])
                {
                    ismodule = FALSE;
                    break;
                }
                //要查询的名称不等于目标名称
                if (srcnamebuf[i] == '\0' && dstnamebuf[i] != '\0')
                {
                    ismodule = FALSE;
                    break;
                }
                ismodule = TRUE;
            }
            //要查找的字符串完全相同
            if (ismodule == TRUE)
            {
                hret = (HMODULE)*((int*)(pcurrentlst + 0x18));
                break;
            }

            //遍历到下一次之前，请空本次的目标比较字符串缓冲区
            for (int i = 0; dstnamebuf[i] != '\0'; i++)
            {
                dstnamebuf[i] = '\0';
            }

            //如果正好一圈,退出循环
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
    IMAGE_FILE_HEADER* lpFileHead = &lpNtHead->FileHeader;//文件头地址
    IMAGE_OPTIONAL_HEADER32* lpOptionalHeader = &lpNtHead->OptionalHeader;//可选头地址
    IMAGE_DATA_DIRECTORY* lpDirectory = lpOptionalHeader->DataDirectory;//数据目录地址

    DWORD lpImportTable = lpOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    DWORD dwSizeofSection = lpFileHead->NumberOfSections;//节表数量
    DWORD dwSizeOfOptional = lpFileHead->SizeOfOptionalHeader;//可选头大小
    IMAGE_SECTION_HEADER* lpSection = (IMAGE_SECTION_HEADER*)((char*)lpOptionalHeader + dwSizeOfOptional);//节表首地址

    DWORD dwSizeOfImage = lpOptionalHeader->SizeOfImage;
    DWORD dwImageBase = lpOptionalHeader->ImageBase;//映像基址
    lpImportTable += dwImageBase;//导入表地址
    DWORD dwAddressOfEntryPoint = lpOptionalHeader->AddressOfEntryPoint;//程序入口点
    dwAddressOfEntryPoint += dwImageBase;
    DWORD dwSizeOfHead = lpOptionalHeader->SizeOfHeaders;
    DWORD dwOldProtect = 0;
    if (pEnv->pfnVirtualProtect((VOID*)dwImageBase, dwSizeOfImage, PAGE_EXECUTE_READWRITE, &dwOldProtect) == 0)
    {
        return false;
    }

    //拷贝头部
    mymemcpy((void*)dwImageBase, PeFile, dwSizeOfHead);
    //解析节表
    for (ULONG i = 0; i < dwSizeofSection; i++)
    {
        //修正内存节表起始地址
        DWORD dwVirAddress = lpSection->VirtualAddress;
        dwVirAddress += dwImageBase;
        //文件偏移
        DWORD dwFileOffset = lpSection->PointerToRawData;
        //大小
        DWORD dwSizeOfSection = lpSection->SizeOfRawData;
        //拷贝节数据
        mymemcpy((void*)dwVirAddress, ((char*)PeFile + dwFileOffset), dwSizeOfSection);
        lpSection++;
    }

    //填入IAT
    IMAGE_IMPORT_DESCRIPTOR  ZeroImport;
    mymemset(&ZeroImport, 0, sizeof(ZeroImport));
    while (mymemcmp(&ZeroImport, (void*)lpImportTable, sizeof(IMAGE_IMPORT_DESCRIPTOR)) != 0)
    {
        IMAGE_IMPORT_DESCRIPTOR* lpCuurentImport = (IMAGE_IMPORT_DESCRIPTOR*)lpImportTable;
        lpImportTable += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        //修正
        DWORD lpIat = lpCuurentImport->FirstThunk;
        lpIat += dwImageBase;
        //检查是否是无效pe
        if (*(DWORD*)lpIat == 0)   
        {
            continue;

        }
        DWORD lpInt = lpCuurentImport->OriginalFirstThunk;
        if (lpInt == NULL)
        {
            lpInt = lpCuurentImport->FirstThunk;
        }
        //修正INT
        lpInt += dwImageBase;
        //无效项
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
            //字符串导出
            if (((*(DWORD*)lpInt) & 0x80000000) == 0)
            {
                lpFun = (DWORD)((char*)(*(DWORD*)lpInt) + dwImageBase + 2);
            }
            //序号导出
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
    //汇编获得基本信息
    ULONG BeingDebugged = 0;
    ULONG NtGlobalFlag = 0;
    //取BeingDebugged
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