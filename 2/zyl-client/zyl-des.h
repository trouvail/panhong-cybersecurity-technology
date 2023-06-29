#pragma once
#include "windows.h"
#include "stdio.h"
#include <time.h>
#include "StaticArray.h"
typedef int INT32;

class DesOpe
{
public:
	short groupCount;
	short keyArray[16][48];//16轮迭代密钥
	short textArray[17][64];//明文数组
	short ciphArray[17][64];//密文数组
	char plaintext[255];//记录解密后的明文字符串
	int Bit2Char(short* BitArray);
	INT32 MakeData(char* plaintext);//实现16轮加密或解密迭代中的每一轮，除去初始置换和逆初始置换
	INT32 MakeCiph(short* ciphtext, int k);//进行密文解密
	INT32 MakeKey(char* key);//形成16个密钥中的每一个子密钥，记录到对应数组中
	char* getTime();//返回当前时间
public:
	int encry(int k);
	int decry(int k);
};
DesOpe op;

char* DesOpe::getTime()
{
	time_t timep;
	time(&timep);
	char tmp[64];
	strftime(tmp, sizeof(tmp), "%Y-%m-%d %H:%M:%S", localtime(&timep));
	return tmp;
}
//实现16轮加密
int DesOpe::encry(int k)
{
	bool Debug = false;
	short pR[32] = { 0 }, pL[32] = { 0 }, cR[32] = { 0 }, cL[32] = { 0 };
	//形成L0R0
	for (int i = 0; i < 32; i++)
	{
		pL[i] = op.textArray[k][i];
		pR[i] = op.textArray[k][i + 32];
	}
	if (Debug) {
		printf("\nR0: ");
		for (int i = 0; i < 32; i++)
			printf("%d ", pR[i]);
	}
	//16轮加密，加密过程每一轮用到上一轮结果
	for (int i = 1; i <= 16; i++)
	{
		for (int j = 0; j < 32; j++)
			cL[j] = pR[j];//Li=R(i-1)
		short EP[48] = { 0 }, XOR[48] = { 0 };
		if (Debug && i == 1)
			printf("\nEP:");
		for (int j = 0; j < 48; j++)
		{
			EP[j] = pR[des_E[j] - 1];//EP
			EP[j] = EP[j] ^ op.keyArray[i - 1][j];//异或运算
			if (Debug && i == 1)
				printf("%d ", EP[j]);
		}
		//S盒计算
		short S[32] = { 0 };
		for (int j = 0; j < 8; j++)
		{
			int n = (EP[j * 6] << 1) + EP[j * 6 + 5];//计算行
			int m = (EP[j * 6 + 1] << 3) + (EP[j * 6 + 2] << 2) + (EP[j * 6 + 3] << 1) + EP[j * 6 + 4];//计算列
			short curNum;
			if (n < 2) 
			    curNum = des_S[j][2 * m + n]; 
			else 
				curNum = des_S[j][2 * m + n + 30]; 
			for (int k = j * 4 + 3; k >= j * 4; k--)
			{
				S[k] = curNum % 2;
				curNum = curNum / 2;
			}
		}
		if (Debug && i == 1) {
			printf("\nS[i]: ");
			for (int j = 0; j < 32; j++)
				printf("%d ", S[j]);
		}
		if (Debug && i == 16)
			printf("\nR16:");
		short F[32] = { 0 };
		for (int j = 0; j < 32; j++)
		{
			F[j] = S[des_P[j] - 1];//替换函数F
			cR[j] = F[j] ^ pL[j];//异或
			if (Debug && i == 16)
				printf("%d ", cR[j]);
			//为下一轮准备
			pR[j] = cR[j];
			pL[j] = cL[j];
		}
	}
	//完成16轮了，进行逆初始置换
	short temp[64] = { 0 };
	for (int i = 0; i < 32; i++)
	{
		temp[i] = cR[i];
		temp[i + 32] = cL[i];
	}
	if (Debug)
		printf("\nciphtext[%d]:", k);
	for (int i = 0; i < 64; i++)
	{
		op.ciphArray[k][i] = temp[pc_last[i] - 1];
		if (Debug && i == 1)
			printf("%d ", op.ciphArray[k][i]);
	}
	return 1;
}



INT32 DesOpe::MakeKey(char* key)
{
	bool Debug = false;
	short tmp[64] = { 0 };
	//将key放入到数组
	for (int i = 0; i < 8; i++)
	{
		for (int j = 0; j < 7; j++)
		{
			tmp[i * 8 + 7 - j - 1] = key[i] % 2;
			key[i] = key[i] / 2;
		}
		//设置奇偶校验位
		int count = 0;
		for (int j = 0; j < 7; j++) {
			if (tmp[i * 8 + j])
				count++;
		}
		if (!(count % 2))
			tmp[i * 8 + 7] = 1;
	}
	short Ikey[56];
	//对key进行初始置换，得到IP(K)
	for (int i = 0; i < 56; i++)
	{
		Ikey[i] = tmp[IK[i] - 1];
		if (Debug) {
			printf("%d ", Ikey[i]);
			if ((i + 1) % 14 == 0)
				printf("\n");
		}
	}
	//进行移位
	UINT64 tempKey = 0;
	for (int i = 0; i < 16; i++)
	{
		short tmpK[56];
		if (i == 0 || i == 1 || i == 15)//左移1位
		{
			tmpK[27] = Ikey[0];
			for (int j = 0; j < 27; j++)
				tmpK[j] = Ikey[j + 1];
			tmpK[55] = Ikey[28];
			for (int j = 28; j < 55; j++)
				tmpK[j] = Ikey[j + 1];
			//if(Debug)printf("%d ", tmpK[j]);
		}
		else //左移2位
		{
			tmpK[26] = Ikey[0];
			tmpK[27] = Ikey[1];
			for (int j = 0; j < 26; j++)
				tmpK[j] = Ikey[j + 2];
			tmpK[54] = Ikey[28];
			tmpK[55] = Ikey[29];
			for (int j = 28; j < 54; j++)
				tmpK[j] = Ikey[j + 2];
		}
		//递归传给i+1
		for (int j = 0; j < 56; j++) 
			Ikey[j] = tmpK[j]; 
		//进行Pk选择，形成48位密钥
		if (Debug)
			printf("\ni=%d: ", i);
		for (int j = 0; j < 48; j++)
		{
			op.keyArray[i][j] = tmpK[keychoose[j] - 1];
			if (Debug)printf("%d ", op.keyArray[i][j]);
		}
	}
	return 1;
}


//进行明文解密
INT32 DesOpe::MakeCiph(short* ciphtext, int k)
{
	bool Debug = false;
	if (Debug)
		printf("\nL0'R0':");
	//进行IP置换
	for (int j = 0; j < 64; j++)
		op.ciphArray[16][j] = op.ciphArray[k][pc_first[j] - 1];//置换

	for (int j = 0; j < 64; j++)
	{
		op.ciphArray[k][j] = op.ciphArray[16][j];//覆盖置换结果
		if (Debug)
			printf("%d ", op.ciphArray[k][j]);
	}
	op.decry(k);
	return 1;
}



//进行明文加密
INT32 DesOpe::MakeData(char* plaintext)
{
	bool Debug = false;
	int length = strlen(plaintext);
	int k = length / 8, kex = length % 8;
	if (Debug)
		printf("length:%d k:%d kex:%d\n", strlen(plaintext), k, kex);
	short tmp[64] = { 0 };
	for (int index = 0; index <= k; index++)//将明文拆为数组
	{
		int count = 8;
		if (index == k) //输出到最后了
		{
			if (kex == 0) 
				break; //没有多余的了
			count = kex;
			for (int i = 0; i < 64; i++)
				op.textArray[index][i] = 0;
		}
		for (int i = 0; i < count; i++)
		{
			for (int j = 0; j < 8; j++)
			{
				op.textArray[index][i * 8 + 7 - j] = plaintext[index * 8 + i] % 2;
				plaintext[index * 8 + i] = plaintext[index * 8 + i] / 2;
			}
		}
		if (Debug)
		{
			for (int i = 0; i < 64; i++)
			{
				printf("%d ", op.textArray[index][i]);
				if (!((i + 1) % 8)) { printf("\n"); }
			}
			printf("\n");
		}
	}
	//进行IP置换
	if (kex != 0) 
		k++; 
	op.groupCount = k;
	for (int i = 0; i < k; i++)
	{
		for (int j = 0; j < 64; j++)
			op.textArray[16][j] = op.textArray[i][pc_first[j] - 1];//置换
		for (int j = 0; j < 64; j++)
		{
			op.textArray[i][j] = op.textArray[16][j];//覆盖置换结果
			if (Debug) {
				printf("tA[%d][%d]:", i, j);
				printf("%d ", op.textArray[i][j]);
				if (!((j + 1) % 8)) { printf("\n"); }
			}
		}
		encry(i);
	}
	return 1;
}

//将01串转化为字符串
int DesOpe::Bit2Char(short* BitArray)
{
	char c = 0, count = strlen(op.plaintext);
	for (int i = 0; i < 64; i++)
	{
		c = c * 2 + BitArray[i];
		if ((i + 1) % 8 == 0)
		{
			op.plaintext[count++] = c;
			c = 0;
		}
	}
	return 1;
}


//实现16轮解密
int DesOpe::decry(int k)
{
	bool Debug = false;
	short pR[32] = { 0 }, pL[32] = { 0 }, cR[32] = { 0 }, cL[32] = { 0 };
	//形成L0'R0'
	for (int i = 0; i < 32; i++)
	{
		pL[i] = op.ciphArray[k][i];
		pR[i] = op.ciphArray[k][i + 32];
	}
	//16轮加密，加密过程每一轮用到上一轮结果
	for (int i = 1; i <= 16; i++)
	{
		for (int j = 0; j < 32; j++)
			cL[j] = pR[j];//Li=R(i-1)
		short EP[48] = { 0 }, XOR[48] = { 0 };
		if (Debug && i == 1)printf("\nEP:");
		for (int j = 0; j < 48; j++)
		{
			EP[j] = pR[des_E[j] - 1];//EP
			EP[j] = EP[j] ^ op.keyArray[16 - i][j];//异或运算*************在这里改一下17-i就行
			if (Debug && i == 1)
				printf("%d ", EP[j]);
		}
		//S盒计算
		short S[32] = { 0 };
		for (int j = 0; j < 8; j++)
		{
			int n = (EP[j * 6] << 1) + EP[j * 6 + 5];//计算行
			int m = (EP[j * 6 + 1] << 3) + (EP[j * 6 + 2] << 2) + (EP[j * 6 + 3] << 1) + EP[j * 6 + 4];//计算列
			//if (Debug) { printf("\nn:%d,m:%d", n, m); }
			short curNum;
			if (n < 2)
				curNum = des_S[j][2 * m + n];
			else
				curNum = des_S[j][2 * m + n + 30];
			//if (Debug) { printf("\ncurNum:%d", curNum); }
			for (int k = j * 4 + 3; k >= j * 4; k--)
			{
				S[k] = curNum % 2;
				curNum = curNum / 2;
			}
		}
		if (Debug && i == 1) {
			printf("\nS[i]: ");
			for (int j = 0; j < 32; j++)printf("%d ", S[j]);
		}
		if (Debug && i == 1)printf("\nF:");
		short F[32] = { 0 };
		for (int j = 0; j < 32; j++)
		{
			F[j] = S[des_P[j] - 1];//替换函数F
			cR[j] = F[j] ^ pL[j];//异或
			if (Debug && i == 1)
				printf("%d ", cR[j]);
			//为下一轮准备
			pR[j] = cR[j];
			pL[j] = cL[j];
		}
	}
	//完成16轮了，进行逆初始置换
	short temp[64] = { 0 };
	for (int i = 0; i < 32; i++)
	{
		temp[i] = cR[i];
		temp[i + 32] = cL[i];
	}
	if (Debug)
		printf("\nM:");
	for (int i = 0; i < 64; i++)
	{
		op.textArray[k][i] = temp[pc_last[i] - 1];
		if (Debug)
			printf("%d ", op.textArray[k][i]);
	}
	return 1;
}

