#include "MD5.h"

int main(int argc, char* argv[]) { //argc=外部命令参数的个数，argv[]存放各参
    unordered_map<string, void(*)(int, char* [])> OperationMap = { {"-t", Test_Message},{"-h", Help_Message},{"-c", Copy_Message}, {"-v", Validsure_Message}, {"-f", Filesure_Message} };
    if (argc < 2) {
        cout << "参数错误，argc = " << argc << endl;
        return -1;
    }
    string op = argv[1];
    if (OperationMap.find(op) != OperationMap.end()) 
        OperationMap[op](argc, argv);
    return 0;
}