#pragma once
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#define UINT64 unsigned __int64

//公钥的结构体，记录了e和n
class PublicKey
{
public:
	unsigned __int64 nE;
	unsigned __int64 nN;
};
class Paraments
{
public:
	unsigned __int64 d;
	unsigned __int64 n;
	unsigned __int64 e;
};
class RsaParam
{
public:
	unsigned __int64 p;
	unsigned __int64 q;
	unsigned __int64 n;
	unsigned __int64 f;
	unsigned __int64 e;
	unsigned __int64 d;
	unsigned __int64 s;
};

Paraments m_cParament;



//生成公钥和私钥
RsaParam RsaGetParam(void) {
	RsaParam Rsa = { 0 };
	UINT64 t = 0;
	Rsa.p = RandomPrime(16);
	Rsa.q = RandomPrime(16);
	Rsa.n = Rsa.p * Rsa.q;
	Rsa.f = (Rsa.p - 1) * (Rsa.q - 1);
	do {//产生e与f互素
		Rsa.e = rand() % 65536;
		Rsa.e |= 1;
	} while (Gcd(Rsa.e, Rsa.f) != 1);
	Rsa.d = Euclid(Rsa.e, Rsa.f);
	Rsa.s = 0;//记录n的位数
	t = Rsa.n >> 1;
	while (t) {
		Rsa.s++;
		t >>= 1;
	}
	return Rsa;
}
//产生随机的DES密钥
void GenerateDesKey(char* randomKey) {
	srand((unsigned)time(NULL));
	for (int i = 0; i < 8; i++) 
		randomKey[i] = rand() % 93 + 33;
	return;
}



/*
	模的运算
*/
//模乘运算（计算两个数的乘积然后取模）
unsigned __int64 MulMod(unsigned __int64 a, unsigned __int64 b, unsigned __int64 n) {
	return (a % n) * (b % n) % n;
}
//模幂运算（求模下指数幂的快速算法）
unsigned __int64 PowMod(unsigned __int64 base, unsigned __int64 pow, unsigned __int64 n) {
	unsigned __int64 c = 1;
	while (pow) {
		while (!(pow & 1)) {//末位为0，即pow为偶数
			pow >>= 1;//pow右移
			base = MulMod(base, base, n);
		}
		//否则末位为1，拆为两步，先--，再次循环末位为0
		pow--;
		c = MulMod(base, c, n);
	}
	return c;
}

/*
	生成随机的大质数
*/
//Miller-Rabin素数测试算法
long RabinMillerKnl(unsigned __int64 n) {
	unsigned __int64 a, q, k, v;
	q = n - 1;
	k = 0;
	//使n-1=q*2^k，其中q为奇数
	while (!(q & 1)) {//q的末位为0，即q为偶数
		++k;
		q >>= 1;
	}
	//随机选取1<a<n-1
	a = 2 + rand() % (n - 3);
	v = PowMod(a, q, n);
	if (v == 1) //如果a^q mod n == 1，则可能为素数
		return 1;
	//逐个尝试，若对所有1<=j<=k-1，有a^(q*2^j) mod n != -1，则n为合数
	for (int j = 0; j < k; j++) {
		unsigned int z = 1;
		//得到z=2^j
		for (int w = 0; w < j; w++) 
			z *= 2;
		if (PowMod(a, z * q, n) == n - 1) //可能为质数
			return 1;
	}
	return 0;
}
//多次运行Miller-Rabin素数测试算法，以减少误判概率
long RabinMiller(unsigned __int64& n, long loop) {
	for (long i = 0; i < loop; i++) {
		if (!RabinMillerKnl(n)) //如果在某轮Miller-Rabin素数测试中不通过，则n为合数
			return 0;
	}
	//通过了loop轮测试，则为素数
	return 1;
}
//最终的质数生成函数
unsigned __int64 RandomPrime(int bits) {
	unsigned __int64 base;
	do {
		base = (unsigned long)1 << (bits - 1);//保证最高位是1
		base += rand() % base;//再加上一个随机数
		base |= 1;//保证最低位是1，即保证是奇数
	} while (!RabinMiller(base, 30));//进行Miller-Rabin素数测试30次
	//printf("base:%I64u\n", base);
	return base;//每轮Miller-Rabin素数测试都通过，则为素数
}



/*
	密钥分配
*/
//加密函数Encry，通过参数cKey传递公钥
unsigned __int64 Encry(unsigned short nSorce, PublicKey& cKey) {
	return PowMod(nSorce, cKey.nE, cKey.nN);//nSorce为明文
}
//解密函数Decry
unsigned short Decry(UINT64 nSorce) {
	UINT64 nRes = PowMod(nSorce, m_cParament.d, m_cParament.n);
	unsigned short* pRes = (unsigned short*)&(nRes);//得到nRes的地址
	if (pRes[1] != 0 || pRes[2] != 0 || pRes[3] != 0) 
		return 0;//解密后得到16位的数字，后面六个字节必然为空，否则错误
	else 
		return pRes[0];
}


/*
	求最大公约数
*/
//通过欧几里得辗转相除法求最大公约数
unsigned __int64 Gcd(unsigned __int64& p, unsigned __int64& q) {
	unsigned __int64 a = p > q ? p : q;//得到p和q中的较大值
	unsigned __int64 b = p < q ? p : q;//得到p和q中的较小值
	unsigned __int64 t;
	if (p == q) {
		return p;//相等，则公约数就是自身
	}
	else {
		while (b) {//辗转相除法
			a = a % b;
			t = a;
			a = b;
			b = t;
		}
		return a;
	}
}
/*
	私钥生成
*/
//私钥生成，等价于寻找方程e*d = Φ(n)*i+1的整数解
unsigned __int64 Euclid(unsigned __int64 e, unsigned __int64 t_n) {
	unsigned __int64 Max = 0xffffffffffffffff - t_n;
	unsigned __int64 i = 1;
	while (1) {
		if (((i * t_n) + 1) % e == 0) 
			return ((i * t_n) + 1) / e;
		i++;
		unsigned __int64 Tmp = (i + 1) * t_n;
		if (Tmp > Max) //超出最大值，不再计算
			return 0;
	}
	return 0;
}



//公钥获取函数
PublicKey GetPublicKey() {
	PublicKey cTmp;
	cTmp.nE = m_cParament.e;
	cTmp.nN = m_cParament.n;
	return cTmp;
}