#pragma once
#include "ShellCode.h"

int GO()
{
    //��ʼ��ָ�뻷��
    ENVIRONMENT FunPtr;
    InitFunPtr(&FunPtr);
    //ѹ�����ݵĵ�ַ
    LPBYTE CompressDataBuffer = NULL;
    //ѹ����Ĵ�С
    ULONG CompressSize = 0;
    //��ѹ����Ĵ�С
    ULONG UnPackCompressSize = 0;
    //��λѹ������
    FindCompressData(CompressDataBuffer, &CompressSize, &UnPackCompressSize);
    //��ѹ��
    LPBYTE UnPackCompressDataBuf = NULL;
    UnPackCompressData(&FunPtr, CompressDataBuffer, CompressSize, UnPackCompressSize, &UnPackCompressDataBuf);

    //loadpe������װ��PE�������޸�IAT���ض�λ
    LoadPe(&FunPtr, UnPackCompressDataBuf);

    return 0;
}

