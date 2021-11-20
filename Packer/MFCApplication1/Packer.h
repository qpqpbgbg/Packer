#pragma once
class CPacker
{
public:
    CPacker();
    ~CPacker();

public:
    //�ӿ����
    BOOL Pack(char *SrcPePath, char * DstPePath);

//�ͼӿǲ�����ͬ��˳��
private:
    //����PE�ļ���1�ɹ���0ʧ��
    BOOL ParsingPe(char *SrcPePath);
    //ѹ������,ʹ��΢���ѹ�����������������ļ��ܣ��޸�����ӿں�������
    BOOL CompressedData();
    //���Shell����
    BOOL GetShellCode();
    //����ѹ�����ݵĽ���
    BOOL MakeCompressData();
    //����Shell����Ľ���
    BOOL MakeShellCodeSectionData();
    //����ڱ�
    BOOL MakeSectionTable();
    //������PEͷ
    BOOL MakePeHead();
    //д����PE
    BOOL WriteNewPeFile(char *DstPePath);

private:
    //ԴPE�ļ�·��
    HANDLE hSrcPeFile;
    //ԴPE�ļ�ӳ����
    HANDLE hSrcPeMappingFile;
    //ԴPE�ļ�ӳ����׵�ַ
    LPBYTE lpSrcPeView = NULL;

    //ԴPE�ļ�DOSͷ
    IMAGE_DOS_HEADER *SrcDosHead;
    //ԴPE�ļ�NTͷ
    IMAGE_NT_HEADERS *SrcNtHead;
    //ԴPE�ڱ�����,��һ���ڱ�
    IMAGE_SECTION_HEADER *SrcSecHead;

    //����ѹ����ĵ�ַ
    LPBYTE CompressDataBuff;
    //����ѹ����Ĵ�С
    ULONG CompressDataBuffSize;

    //Shell�����ַ
    LPBYTE lpShellCode;
    //Shell���볤��
    ULONG ShellCodeSize;

    //ѹ���󲢶�������ݻ�������ַ
    LPBYTE AlignCompressDataBuff;
    //�ļ���ѹ���󲢶�������ݳ���
    ULONG AlignCompressDataBuffSize;

    //Shell�����ַ�����Ļ����ַ
    LPBYTE AlignlpShellCode;
    //�ļ���Shell��������ĳ���
    ULONG AlignShellCodeSize;

    //�ӿǺ�ڱ�
    PIMAGE_SECTION_HEADER NewPeSectionTable;
    enum
    {
        SPACE_SECTION, //�ս�����
        CODE_SECTION,  //���������
        DATA_SECTION,  //ѹ�����ݽ�����ֵ
    };

    //��PE��ַ
    LPBYTE NewPeHead;
    ULONG NewPeHeadSize;

//�ӿǲ�������Ҫ�Ĺ���
private:
    //��������Ĵ�С
    ULONG CalcAlign(ULONG NeedAlignValue, ULONG AlignValue);
    //������
    void ErrorMessage();
};

