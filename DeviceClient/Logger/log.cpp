#include "log.h"
#include <iostream>
#include <memory>
#include <cerrno>
#include <cstring>
#include "log_utils.h"

LogType Logger::loglevel_ = LogType::Info;
bool Logger::toStdOut_ = false;
std::string Logger::logdir_;
std::ofstream Logger::fstream_;
std::string Logger::currentLogfile_;

Logger& Logger::Info() {
    static Logger info{LogType::Info};
    return info;
}

Logger& Logger::Error() {
    static Logger error{LogType::Error};
    return error;
}

Logger& Logger::Warn() {
    static Logger warn{LogType::Warn};
    return warn;
}

Logger::Logger(LogType type) : type_{type} {}

int Logger::getFlushThreshold() const { return flushThreshold_; }

void Logger::setFlushThreshold(int flushThreshold) { flushThreshold_ = flushThreshold; }

std::string Logger::getLogdir() { return logdir_; }

void Logger::setLogdir(const std::string& logdir) { logdir_ = logdir; }

std::ostream& operator<<(std::ostream& strm, LogType type) {
    switch (type) {
        case LogType::Info:
            return strm << "Info:";
        case LogType::Warn:
            return strm << "Warning:";
        case LogType::Error:
            return strm << "Error:";
        default:
            return strm << "Type{" << static_cast<int>(type) << "}:";
    }
};

Logger& Logger::operator<<(const std::string& message) {
    if (!logfileIsOpen()) {
        newLogfile();
    }
    if (this->type_ >= loglevel_) {
        std::size_t pos = message.find('\n');
        if (pos != std::string::npos) {
            std::string remaining = message;
            do {
                lineCount_++;
                writeMessage(remaining.substr(0, pos + 1));
                nextLine_ = true;
                remaining = remaining.substr(pos + 1);
            } while ((pos = remaining.find('\n')) != std::string::npos);

            if (!remaining.empty()) {
                writeMessage(remaining);
            }

        } else if (!message.empty()) {
            writeMessage(message);
        }
    }
    return *this;
}

Logger& Logger::operator<<(const char* message) {
    return *this << std::string(message);
}

void Logger::writeMessage(const std::string& message) {
    if (toStdOut_) {
        std::cout << message;
    }
    if (nextLine_) {
        buffer_ << LogUtils::getDateString("-") << " " << LogUtils::getTimeString(":") << " "
                << this->type_ << " ";

        nextLine_ = false;
    }
    buffer_ << message;
    if (shouldFlush()) {
        flushBuffer();
    }
}

bool Logger::shouldFlush() const { return lineCount_ > flushThreshold_; }

bool Logger::logfileIsOpen() { return fstream_.is_open(); }

std::string Logger::newLogfile() {
    std::string filePath = (logdir_.empty() ? "" : logdir_ + "/") +
                           LogUtils::getDateString("") + LogUtils::getTimeString("") +
                           ".log.txt";
    if (logfileIsOpen()) {
        fstream_.close();
        fstream_.clear();
    }

    if (LogUtils::fileExists(filePath)) {
        int suffix = 2;
        std::stringstream strm;
        strm << filePath.substr(0, filePath.find(".log.txt")) << "(" << suffix << ")" << ".log.txt";
        filePath = strm.str();

        while (LogUtils::fileExists(filePath)) {
            ++suffix;
            if (suffix > 9) {
                throw file_open_exception("Too many new logs files opened within too short of a timespan.");
            }
            filePath[filePath.size() - 10] = suffix + 48;
        }
    }

    fstream_.open(filePath);
    if (!fstream_.good()) {
        fstream_.close();
        const std::string err = strerror(errno);
        throw file_open_exception(strerror(errno));
    }

    currentLogfile_ = filePath;
    return filePath;
}

LogType Logger::getLoglevel() { return Logger::loglevel_; }

void Logger::setLoglevel(LogType loglevel) { Logger::loglevel_ = loglevel; }

void Logger::flushBuffer() {
    if (!logfileIsOpen()) {
        return;
    }
    const std::string content = buffer_.str();
    fstream_ << content;
    if (!fstream_.good()) {
        std::cout << strerror(errno) << "\n";
        fstream_.clear();
    }
    buffer_.str(std::string());
    lineCount_ = 0;
}

void Logger::flushOfstream() {
    if (!logfileIsOpen()) {
        return;
    }
    fstream_.flush();
}

std::string Logger::getCurrentLogfileName() {
    return currentLogfile_;
}

bool Logger::getStdout() {
    return toStdOut_;
}

void Logger::setStdout(bool val) {
    toStdOut_ = val;
}
