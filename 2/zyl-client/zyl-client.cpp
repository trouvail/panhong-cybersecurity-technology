#include "iostream"
#include "Client.h"
using namespace std;

int main() {
	char mode[10] = { 0 };
	printf("Client:\n");
	while (1) {
		runClient();
		break;
	}
	system("pause");
	return 1;
}