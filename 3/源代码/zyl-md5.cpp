#include "MD5.h"



// 将1个64位int转成vector<uint8_t>
vector<uint8_t> MD5::FromInt64ToInt8Vec(uint64_t num) {
    vector<uint8_t> result(8);
    uint8_t help = 255;
    for (int i = 0; i < 8; ++i) {
        result[i] = num & help;
        num = num >> 8;
    }
    return result;
}
//对给定长度的字符串进行MD5运算
void MD5::StrUpdate(const string& str) {
    Reset();
    // 首先将输入转化为标准字节流，再调用私有函数Update
    vector<uint8_t> input;
    for (int i = 0; i < str.size(); ++i) 
        input.push_back(str[i]);
    Update(input);
}
// 将64byte（64*8 bit）的数据块划分为16个32bit大小的子分组，input.size()=64
vector<uint32_t> MD5::Decode(const vector<uint8_t>input) {
    // input的4个8bit数字合并成一个output的32bit数字，但是要反过来，ABCD->DCBA
    vector<uint32_t> output;
    for (int i = 0; i < input.size() / 4; ++i) {
        uint32_t temp = 0;
        for (int j = 3; j >= 0; --j) {
            temp += input[i * 4 + j];
            if (j != 0) 
                temp = temp << 8;
        }
        output.push_back(temp);
    }
    return output;
}
// 对文件中的内容进行MD5运算
void MD5::FileUpdate(ifstream& in) {
    Reset();
    string str((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
    vector<uint8_t> input;
    for (int i = 0; i < str.size(); ++i) 
        input.push_back(str[i]);
    Update(input);
}

// decimal是32位十进制的表示，转成16进制，用8个字母的string表示
string MD5::From10To16(uint32_t decimal) {
    string hex;
    uint32_t help = 4026531840;
    unordered_map<int, string> map10To16 = { {0, "0"},  {1, "1"},  {2, "2"},  {3, "3"},
                                             {4, "4"},  {5, "5"},  {6, "6"},  {7, "7"},
                                             {8, "8"},  {9, "9"},  {10, "a"}, {11, "b"},
                                             {12, "c"}, {13, "d"}, {14, "e"}, {15, "f"} };
    for (int i = 0; i < 8; ++i) {
        int tempResult = (decimal & help) >> 28;
        hex += map10To16[tempResult];
        decimal = decimal << 4;
    }
    return hex;
}

// 私有函数Update
// 对长为length的字节流进行预处理，然后再调用transform函数对每一个64byte的数据块进行计算
void MD5::Update(vector<uint8_t> input) {
    vector<uint8_t> trueLen = FromInt64ToInt8Vec(input.size() * 8);// 真实长度，trueLen.size()=8
    vector<uint8_t> fillHelp(64, (uint8_t)0); // 最多填充512bit=64*8
    fillHelp[0] = (uint8_t)128;

    if (input.size() * 8 % 512 == 448) 
        input.insert(input.end(), fillHelp.begin(), fillHelp.end());
    else {
        int index = 0;
        while (input.size() * 8 % 512 != 448) 
            input.push_back(fillHelp[index++]);
    }
    input.insert(input.end(), trueLen.begin(), trueLen.end());

    // 开始MD5运算
    int transformTime = input.size() / 64;
    for (int i = 0; i < transformTime; ++i) {
        vector<uint8_t> md5input;
        md5input.insert(md5input.end(), input.begin() + i * 64, input.begin() + (i + 1) * 64);
        Transform(md5input);
    }
}
