#include "iostream"
#include "Server.h"
using namespace std;

int main() {
	char mode[10] = { 0 };
	printf("Server:\n");
	while (1) {
		runServer();
		break;
	}
	system("pause");
	return 1;
}