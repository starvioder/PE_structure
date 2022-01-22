# include"PE.h"
using namespace std;


int main() {
	char str[50] ;
	cout << "请输入要查询的文件路径" << endl;
	cin >> str;
	
	printNTHeader(str);
}