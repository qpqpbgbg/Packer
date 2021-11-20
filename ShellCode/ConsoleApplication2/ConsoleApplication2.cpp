#pragma once
#include "ShellCode.h"

int GO()
{
    //初始化指针环境
    ENVIRONMENT FunPtr;
    InitFunPtr(&FunPtr);
    //压缩数据的地址
    LPBYTE CompressDataBuffer = NULL;
    //压缩后的大小
    ULONG CompressSize = 0;
    //加压缩后的大小
    ULONG UnPackCompressSize = 0;
    //定位压缩数据
    FindCompressData(CompressDataBuffer, &CompressSize, &UnPackCompressSize);
    //解压缩
    LPBYTE UnPackCompressDataBuf = NULL;
    UnPackCompressData(&FunPtr, CompressDataBuffer, CompressSize, UnPackCompressSize, &UnPackCompressDataBuf);

    //loadpe，重新装载PE，包括修复IAT，重定位
    LoadPe(&FunPtr, UnPackCompressDataBuf);

    return 0;
}

