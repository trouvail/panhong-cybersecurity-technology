#include "Function.h"
//对不同种类函数的定义
#define F(x, y, z) (((x) & (y)) | ((~x) & (z))) //F函数
#define G(x, y, z) (((x) & (z)) | ((y) & (~z))) //G函数
#define H(x, y, z) ((x) ^ (y) ^ (z)) //H函数
#define I(x, y, z) ((y) ^ ((x) | (~z)))  //I函数
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n)))) //32位数字x的循环左移n位操作

#define FF(a, b, c, d, x, s, ac) { (a) += F ((b), (c), (d)) + (x) + ac; (a) = ROTATE_LEFT ((a), (s)); (a) += (b); }
#define GG(a, b, c, d, x, s, ac) { (a) += G ((b), (c), (d)) + (x) + ac; (a) = ROTATE_LEFT ((a), (s)); (a) += (b); }
#define HH(a, b, c, d, x, s, ac) { (a) += H ((b), (c), (d)) + (x) + ac; (a) = ROTATE_LEFT ((a), (s)); (a) += (b); }
#define II(a, b, c, d, x, s, ac) { (a) += I ((b), (c), (d)) + (x) + ac; (a) = ROTATE_LEFT ((a), (s)); (a) += (b); }

#define T(i) 4294967296 * abs(sin(i))

/* 主要功能：
1、为任意长度的字符串生成 MD5 摘要
2、为任意大小的文件生成 MD5 摘要
3、利用 MD5 摘要验证文件的完整性
*/
class MD5 {
public:
    void StrUpdate(const string& str); 
    void FileUpdate(ifstream& in); 
    string Tostring(); 

private:
    void Reset(); 
    void Update(vector<uint8_t> input); 
    void Transform(const vector<uint8_t> block); 
    vector<uint32_t> Decode(const vector<uint8_t>input); 
    string From10To16(uint32_t decimal); 
    vector<uint8_t> FromInt64ToInt8Vec(uint64_t num); 
    uint32_t state[4]; 
};