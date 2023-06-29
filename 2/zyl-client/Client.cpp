#include <windows.h>
#include <stdio.h>
#include "Client.h"
#include"zyl-rsa.h"
#include "zyl-des.h"
#include<math.h>
#pragma comment(lib,"ws2_32.lib")


int runClient()
{
	//1.加载套接字库
	WORD wVersionRequested;
	WSADATA wsaData;
	wVersionRequested = MAKEWORD(2, 2);
	int err = WSAStartup(wVersionRequested, &wsaData);
	if (err) 
		printf("C: 加载socket连接失败\n"); 
	else 
		printf("C: 加载socket连接成功\n"); 
	//2.创建一个套接字供使用
	SOCKET ServerSocket = socket(AF_INET, SOCK_STREAM, 0);
	//3.向服务器发出连接请求
	SOCKADDR_IN socksin;//记录服务器端地址
	socksin.sin_family = AF_INET;
	socksin.sin_port = htons(6020);
	socksin.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
	int rf = connect(ServerSocket, (SOCKADDR*)&socksin, sizeof(socksin));
	if (rf == SOCKET_ERROR)
		printf("C: 与服务器连接失败\n");
	else
	{
		printf("C: 与服务器连接成功\n");

		char publicKey[100] = { 0 };
		recv(ServerSocket, publicKey, 100, 0);
		printf("C: 从服务器接收到公钥:%s\n", publicKey);
		char sN[100], sE[100];
		int pN = 0, pE = 0;
		bool divide = false;
		for (int i = 0; i < strlen(publicKey); i++)
		{
			if (publicKey[i] == ',') { divide = true; continue; }
			if (!divide) 
				sN[pN++] = publicKey[i];
			else 
				sE[pE++] = publicKey[i];
		}
		PublicKey rsaPublic;
		rsaPublic.nE = atoi(sE);
		rsaPublic.nN = atoll(sN);
		char encryKey[300];

		char desKey[8] = { 0 }, plaintext[255], zhouyanlin_ciphenof[500] = { 0 };
		GenerateDesKey(desKey);
		printf("C: 随机生成DES密钥:");
		for (int i = 0; i < 8; i++) {
			printf("%c", desKey[i]);
		}
		printf("\n");
		//scanf("%s", desKey);
		char tempK[8];
		strcpy(tempK, desKey);
		op.MakeKey(tempK);
		int p = 0;
		for (int i = 0; i < 4; i++) {
			int p1 = i * 2, p2 = i * 2 + 1;
			int num1 = int(desKey[p1]);
			int num2 = int(desKey[p2]);
			UINT64 curNum = (num1 << 8) + num2;
			UINT64 encry = Encry(curNum, rsaPublic);
			char cencry[20];
			sprintf(cencry, "%lu", encry);
			strncpy(encryKey + p, cencry, strlen(cencry));
			p += strlen(cencry);
			char divide = ',';
			encryKey[p] = divide;
			p += 1;
		}
		encryKey[p] = '\0';
		//发送加密的DES密钥给给服务器
		printf("C: 向服务器发送加密的DES密钥:%s\n", encryKey);
		send(ServerSocket, encryKey, p, 0);


		while (1)
		{  //发送密文信息
			printf("C: 请输入明文:");
			setbuf(stdin, NULL);
			scanf("%[^\n]s", plaintext);//使得空行代表读取完毕而不是空格
			bool exit = false;
			if (strcmp(plaintext, "exit") == 0) { exit = true; }
			op.MakeData(plaintext);
			int count = 0;
			char time[64];
			strcpy(time, op.getTime());
			printf("C: [%s]向服务器发送密文:", time);
			for (int i = 0; i < op.groupCount; i++)
			{
				for (int j = 0; j < 64; j++)
					zhouyanlin_ciphenof[count++] = op.ciphArray[i][j] + 48;//要加上48
			}
			zhouyanlin_ciphenof[count] = '\0';
			int zhouyanlin_ciphenofs[32];
			int asc = 0;
			for (int i = 0; i < count; i++) {
				int sub = zhouyanlin_ciphenof[i] - 48;
				sub = sub * pow(2, (7 - i % 8));
				asc += sub;
				if (i % 8 == 7) {
					zhouyanlin_ciphenofs[i / 8] = asc;
					asc = 0;
				}
			}
			for (int i = 0; i < count / 8; i++)
				printf("%d,", zhouyanlin_ciphenofs[i]);
			//发送数据给服务器
			send(ServerSocket, zhouyanlin_ciphenof, strlen(zhouyanlin_ciphenof), 0);
			if (exit) 
				break; 
			//利用返回的套接字和服务器通信，接收加密信息
			char s[256] = { 0 };
			recv(ServerSocket, s, 256, 0);
			int counts = strlen(s);
			int asc_recv = 0;
			int s1[32];
			for (int i = 0; i < counts; i++) {
				int sub = s[i] - 48;
				sub = sub * pow(2, (7 - i % 8));
				asc_recv += sub;
				if (i % 8 == 7) {
					s1[i / 8] = asc_recv;
					asc_recv = 0;
				}
			}
			printf("\nC: 接收服务器的密文:");
			for(int i=0;i<counts/8;i++)
				printf("%d,", s1[i]);
			printf("\n");
			memset(op.plaintext, 0, sizeof(op.plaintext));//初始化明文
			//收到加密信息后，进行解密
			op.groupCount = 0;
			for (int i = 0; i < strlen(s); i++)//拆解收到的加密信息，转为二进制数组
			{
				op.ciphArray[op.groupCount][i % 64] = s[i] - 48;
				if ((i + 1) % 64 == 0)
					op.groupCount++;
			}
			for (int i = 0; i < op.groupCount; i++)
				op.MakeCiph(op.ciphArray[i], i);
			//输出解密后的明文
			strcpy(time, op.getTime());
			printf("C: [%s]经过解密后的明文:", time);
			for (int i = 0; i < op.groupCount; i++)
				op.Bit2Char(op.textArray[i]);
			printf("%s\n", op.plaintext);
			if (strcmp(op.plaintext, "exit") == 0) 
				break; 
		}
		//如果用户选择退出，则向服务器发送退出请求
		printf("\nC: 退出...");
	}
	closesocket(ServerSocket);
	WSACleanup();
	return 0;
}