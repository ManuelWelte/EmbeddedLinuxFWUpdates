//
// Created by manuel on 05.01.21.
//

#ifndef LOGGER_LOG_UTILS_H
#define LOGGER_LOG_UTILS_H

#include <chrono>
#include <iomanip>
#include "unistd.h"

class LogUtils {
public:

    static bool fileExists(const std::string& path) {
        return access(path.c_str(), F_OK) == 0;
    }

    static std::string getDateString(const std::string& separator) {
        std::stringstream formatStream;
        formatStream << "%Y" << separator << "%m" << separator << "%d";
        return getLocaltime(formatStream.str());
    }

    static std::string getTimeString(const std::string& separator) {
        std::stringstream formatStream;
        formatStream << "%H" << separator << "%M" << separator << "%S";
        return getLocaltime(formatStream.str());
    }

private:
    static std::string getLocaltime(const std::string& format) {
        auto now = std::chrono::system_clock::now();
        time_t now_tt = std::chrono::system_clock::to_time_t(now);
        std::stringstream timestream;
        timestream << std::put_time(std::localtime(&now_tt), format.c_str());
        return timestream.str();
    }
};

#endif //LOGGER_LOG_UTILS_H
