#pragma once
class CPacker
{
public:
    CPacker();
    ~CPacker();

public:
    //加壳入口
    BOOL Pack(char *SrcPePath, char * DstPePath);

//和加壳步骤相同的顺序
private:
    //解析PE文件，1成功，0失败
    BOOL ParsingPe(char *SrcPePath);
    //压缩数据,使用微软的压缩函数，如果后期想改加密，修改这个接口函数即可
    BOOL CompressedData();
    //获得Shell代码
    BOOL GetShellCode();
    //构造压缩数据的节区
    BOOL MakeCompressData();
    //构造Shell代码的节区
    BOOL MakeShellCodeSectionData();
    //构造节表
    BOOL MakeSectionTable();
    //构造新PE头
    BOOL MakePeHead();
    //写入新PE
    BOOL WriteNewPeFile(char *DstPePath);

private:
    //源PE文件路径
    HANDLE hSrcPeFile;
    //源PE文件映像句柄
    HANDLE hSrcPeMappingFile;
    //源PE文件映射的首地址
    LPBYTE lpSrcPeView = NULL;

    //源PE文件DOS头
    IMAGE_DOS_HEADER *SrcDosHead;
    //源PE文件NT头
    IMAGE_NT_HEADERS *SrcNtHead;
    //源PE节表区域,第一个节表
    IMAGE_SECTION_HEADER *SrcSecHead;

    //数据压缩后的地址
    LPBYTE CompressDataBuff;
    //数据压缩后的大小
    ULONG CompressDataBuffSize;

    //Shell代码地址
    LPBYTE lpShellCode;
    //Shell代码长度
    ULONG ShellCodeSize;

    //压缩后并对齐的数据缓冲区地址
    LPBYTE AlignCompressDataBuff;
    //文件中压缩后并对齐的数据长度
    ULONG AlignCompressDataBuffSize;

    //Shell代码地址对齐后的缓冲地址
    LPBYTE AlignlpShellCode;
    //文件中Shell代码对齐后的长度
    ULONG AlignShellCodeSize;

    //加壳后节表
    PIMAGE_SECTION_HEADER NewPeSectionTable;
    enum
    {
        SPACE_SECTION, //空节索引
        CODE_SECTION,  //代码节索引
        DATA_SECTION,  //压缩数据节索引值
    };

    //新PE地址
    LPBYTE NewPeHead;
    ULONG NewPeHeadSize;

//加壳步骤中需要的功能
private:
    //计算对齐后的大小
    ULONG CalcAlign(ULONG NeedAlignValue, ULONG AlignValue);
    //报错函数
    void ErrorMessage();
};

