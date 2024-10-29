#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>

#define FILE_MAGIC 0x7f4b5355 // ' KSU', u32
#define FILE_FORMAT_VERSION 3 // u32
#define KSU_MAX_PACKAGE_NAME 256

struct root_profile {
    int32_t uid;
    int32_t gid;
    int32_t groups_count;
    int32_t groups[32];
    struct {
        uint64_t effective;
        uint64_t permitted;
        uint64_t inheritable;
    } capabilities;
    char selinux_domain[64];
    int32_t namespaces;
};

struct non_root_profile {
    bool umount_modules;
};

struct AppProfile {
    uint32_t version;
    char key[KSU_MAX_PACKAGE_NAME];
    int32_t current_uid;
    bool allow_su;
    union {
        struct {
            bool use_default;
            char template_name[KSU_MAX_PACKAGE_NAME];
            root_profile profile;
        } rp_config;
        struct {
            bool use_default;
            non_root_profile profile;
        } nrp_config;
    };
};

std::vector<AppProfile> allow_list;
bool default_umount = false;

void load_allow_list(const std::string &filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        exit(1);
    }

    uint32_t magic, version;
    file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    file.read(reinterpret_cast<char*>(&version), sizeof(version));

    if (magic != FILE_MAGIC || version != FILE_FORMAT_VERSION) {
        std::cerr << "Invalid file format" << std::endl;
        exit(2);
    }

    while (file) {
        AppProfile profile;
        file.read(reinterpret_cast<char*>(&profile), sizeof(profile));

        if (file) {
            allow_list.push_back(profile);
        }
    }

    std::cout << "Loaded " << allow_list.size() << " profiles from allowlist." << std::endl;
}

void load_config(const std::string &filename) {
    std::ifstream file(filename);
    if (!file) {
        std::cerr << "Failed to open config file: " << filename << std::endl;
        exit(3);
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.find("default_umount") != std::string::npos) {
            int value = std::stoi(line.substr(line.find(" ") + 1));
            default_umount = (value == 1);
            std::cout << "Config: default_umount = " << default_umount << std::endl;
        }
    }
}

bool check_package(const std::string &package) {
    // 特殊处理 me.weishu.kernelsu
    if (package == "me.weishu.kernelsu") {
        return false;
    }

    for (const auto &profile : allow_list) {
        if (std::strcmp(profile.key, package.c_str()) == 0) {
            if (profile.allow_su) {
                return false;
            } else if (profile.nrp_config.profile.umount_modules) {
                return true;
            } else if (profile.nrp_config.use_default) {
                return default_umount;
            } else {
                return false;
            }
        }
    }
    return default_umount;
}

int main() {
    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        std::cerr << "Failed to get current working directory" << std::endl;
        return 4;
    }

    std::string allowlist_path = std::string(cwd) + "/.allowlist";
    std::string config_path = std::string(cwd) + "/config.txt";
    std::string dump_path = std::string(cwd) + "/dump.txt";

    load_allow_list(allowlist_path);
    load_config(config_path);

    FILE *fp = popen("pm list packages", "r");
    if (fp == NULL) {
        std::cerr << "Failed to run pm list packages" << std::endl;
        return 5;
    }

    std::ofstream dump_file(dump_path);
    if (!dump_file) {
        std::cerr << "Failed to open dump file: " << dump_path << std::endl;
        return 6;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp) != NULL) {
        std::string package(line);
        package = package.substr(8); // 删除前缀 "package:"
        package.erase(package.find_last_not_of(" \n\r\t") + 1); // 去除尾部的空白字符

        bool result = check_package(package);
        if (result) {
            dump_file << package << std::endl;
        }
    }

    pclose(fp);
    dump_file.close();

    return 0;
}

