#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "Server.h"
#include "zyl-des.h"
#include"zyl-ope.h"
#include<math.h>
#pragma comment(lib,"ws2_32.lib")

extern Paraments m_cParament;

int runServer()
{
	//1.加载套接字库
	WORD wVersionRequested = MAKEWORD(2, 2);
	WSADATA wsaData;
	int err = WSAStartup(wVersionRequested, &wsaData);
	if (err) 
		printf("S: 加载socket连接失败\n"); 
	else 
		printf("S: 加载socket连接成功\n"); 

	//2.创建一个套接字供使用
	SOCKET ServerSocket = socket(AF_INET, SOCK_STREAM, 0);

	//3.将套接字绑定到本地地址和端口上
	SOCKADDR_IN addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(6020);
	addr.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
	bind(ServerSocket, (SOCKADDR*)&addr, sizeof(SOCKADDR));

	//4.将套接字设置为监听模式，以接收客户端请求
	err = listen(ServerSocket, 5);
	if (err)
		printf("S: 未监听到对方客户端\n"); 
	else 
		printf("S: 成功监听到对方客户端\n"); 

	//5.等待并接收客户端请求，返回新的连接套接字
	SOCKADDR_IN addr_out;
	int len = sizeof(SOCKADDR);
	SOCKET ClientSocket = accept(ServerSocket, (SOCKADDR*)&addr_out, &len);

	//6.计算密钥	
	char desKey[10] = { '\n' };
	RsaParam rsaParam = RsaGetParam();
	m_cParament.d = rsaParam.d;
	m_cParament.e = rsaParam.e;
	m_cParament.n = rsaParam.n;
	PublicKey publicKey = GetPublicKey();
	char cpublicKey[100], sN[100], sE[100];
	sprintf(sN, "%lu", publicKey.nN);
	itoa(publicKey.nE, sE, 10);
	strcpy(cpublicKey, sN);
	int p1 = strlen(sN), p2 = strlen(sE);
	cpublicKey[p1] = ',';
	strncpy(cpublicKey + p1 + 1, sE, p2);
	cpublicKey[p1 + p2 + 1] = '\0';
	printf("S: 向客户端发送公钥和加密密钥:%s\n", cpublicKey);
	send(ClientSocket, cpublicKey, strlen(cpublicKey), 0);
	//接收加密后的DES密钥
	char encryKey[300] = { '\0' };
	recv(ClientSocket, encryKey, 300, 0);//接收密钥
	printf("S: 从客户端接收加密后的DES密钥:%s\n", encryKey);
	int k = 0;
	for (int i = 0; i < 4; i++) {
		char cencry[20] = { '\0' };
		int p = 0;
		while (encryKey[k++] != ',') 
			cencry[p++] = encryKey[k - 1];
		UINT64 encry = atoll(cencry);
		UINT64 decry = Decry(encry);
		desKey[i * 2] = decry >> 8;
		desKey[i * 2 + 1] = decry % 256;
	}
	printf("S: 密钥解密后:%s", desKey);
	op.MakeKey(desKey);
	while (1)
	{
		memset(op.plaintext, 0, sizeof(op.plaintext));//初始化明文
		//利用返回的套接字和客户端通信
		char s[256] = { 0 };
		recv(ClientSocket, s, 256, 0);//接收密文
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
		printf("\nS: 接收客户端的密文:");
		for (int i = 0; i < counts / 8; i++)
			printf("%d,", s1[i]);
		printf("\n");
		//拆解收到的加密信息，转为二进制数组
		op.groupCount = 0;
		//printf("%d\n", strlen(s));
		for (int i = 0; i < strlen(s); i++)
		{
			op.ciphArray[op.groupCount][i % 64] = s[i] - 48;
			if ((i + 1) % 64 == 0) 
				op.groupCount++; 
		}
		//进行密文的解密
		for (int i = 0; i < op.groupCount; i++)
			op.MakeCiph(op.ciphArray[i], i);
		//输出解密后的明文
		char time[64];
		strcpy(time, op.getTime());
		printf("S: [%s]经过解密后的明文:", time);
		for (int i = 0; i < op.groupCount; i++)
			op.Bit2Char(op.textArray[i]);
		printf("%s\n", op.plaintext);
		if (strcmp(op.plaintext, "exit") == 0) 
			break;


		//如果用户需要继续发送信息，则继续发送
		char plaintext[255] = { 0 }, zhouyanlin_cipherte[500] = { 0 };
		printf("S: 请输入明文:");
		setbuf(stdin, NULL);
		scanf("%[^\n]s", plaintext);//使得空行代表读取完毕而不是空格
		bool exit = false;
		if (strcmp(plaintext, "exit") == 0) 
		   exit = true; 
		op.MakeData(plaintext);
		int count = 0;
		strcpy(time, op.getTime());
		printf("S: [%s]向客户端发送密文:", time);
		for (int i = 0; i < op.groupCount; i++)
		{
			for (int j = 0; j < 64; j++)
				zhouyanlin_cipherte[count++] = op.ciphArray[i][j] + 48;//要加上48
		}
		zhouyanlin_cipherte[count] = '\0';
		int zhouyanlin_ciphertes[32];
		int asc = 0;
		for (int i = 0; i < count; i++) {
			int sub = zhouyanlin_cipherte[i] - 48;
			sub = sub * pow(2, (7 - i % 8));
			asc += sub;
			if (i % 8 == 7) {
				zhouyanlin_ciphertes[i / 8] = asc;
				asc = 0;
			}
		}
		for (int i = 0; i < count / 8; i++)
			printf("%d,", zhouyanlin_ciphertes[i]);
		//发送数据给服务器
		send(ClientSocket, zhouyanlin_cipherte, strlen(zhouyanlin_cipherte), 0);
		if (exit) 
			break; 
	}
	printf("\nS: 退出...");

	//关闭套接字
	closesocket(ServerSocket);
	WSACleanup();
	return 0;
}