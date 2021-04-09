//
// Created by manuel on 03.01.21.
//
#include <gtest/gtest.h>
#include "log.h"
#include <sstream>
#include <experimental/filesystem>
#include "log_utils.h"

namespace fs = std::experimental::filesystem;
const std::string test_log_dir("test_logs");

class LogTest : public ::testing::Test {
protected:
    void SetUp() override {
        Logger::setLogdir(test_log_dir);
        Logger::setLoglevel(LogType::Info);
        Logger::Error().setFlushThreshold(0);
        Logger::Info().setFlushThreshold(0);
        Logger::Warn().setFlushThreshold(0);
    }

public:
    static void SetUpTestSuite() {
        fs::create_directory(test_log_dir);
    }

    static void TearDownTestSuite() {
        fs::remove_all(test_log_dir);
    }
};


TEST_F(LogTest, newLogFileTestShouldSucceed) {
    std::string result;
    ASSERT_NO_THROW(result = Logger::newLogfile());
    ASSERT_STRNE(result.c_str(), "");
    ASSERT_FALSE(result.find(".log.txt") == std::string::npos);
}

TEST_F(LogTest, newLogFileTestShouldThrowException) {
    Logger::setLogdir("nonsense");
    ASSERT_THROW(Logger::newLogfile(), file_open_exception);
}

TEST_F(LogTest, newLogFileTestAlternating) {
    ASSERT_NO_THROW(Logger::newLogfile());
    Logger::setLogdir("nonsense");
    ASSERT_THROW(Logger::newLogfile(), file_open_exception);
    ASSERT_THROW(Logger::newLogfile(), file_open_exception);
    Logger::setLogdir("test_logs");
    ASSERT_NO_THROW(Logger::newLogfile());
    ASSERT_NO_THROW(Logger::newLogfile());
    Logger::setLogdir("nonsense");
    ASSERT_THROW(Logger::newLogfile(), file_open_exception);
}

TEST_F(LogTest, setLogDirTestShouldFindFile) {
    fs::create_directory("more_test_logs");
    Logger::setLogdir("more_test_logs");
    std::string result = Logger::newLogfile();
    ASSERT_TRUE(fs::exists(result));
    fs::remove_all("more_test_logs");

}

TEST_F(LogTest, getLogDirTestShouldMatchName) {
    std::string dirname = "some_dir_name";
    Logger::setLogdir(dirname);
    ASSERT_STREQ(Logger::getLogdir().c_str(), dirname.c_str());
}

TEST_F(LogTest, logFileOpenTestShouldBeOpen) {
    ASSERT_TRUE(Logger::logfileIsOpen());
    Logger::newLogfile();
    ASSERT_TRUE(Logger::logfileIsOpen());
}

TEST_F(LogTest, logFileOpenTestShouldBeClosed) {
    Logger::setLogdir("nonsense");
    try {
        Logger::newLogfile();
    } catch (file_open_exception& e) {

    }
    ASSERT_FALSE(Logger::logfileIsOpen());
}

TEST_F(LogTest, shiftOperatorTestShouldWriteCorrectDatetime) {

    const std::string fname = Logger::newLogfile();
    const std::string errorMsg = "This is an error message.\n";
    Logger::Error() << errorMsg;
    const std::string date = LogUtils::getDateString("-");
    const std::string time = LogUtils::getTimeString(":");
    Logger::flushOfstream();
    std::ifstream logF(fname);
    std::string word;
    logF >> word;
    ASSERT_EQ(word, date);
    logF >> word;
    // Check for equality in hours and minutes
    ASSERT_EQ(word.substr(0, 6), time.substr(0, 6));

}

TEST_F(LogTest, shiftOperatorTestShouldWriteCorrectMessages) {
    const std::string fname = Logger::newLogfile();

    const std::string errorMsg = "This is an error message.";
    const std::string warnMsg = "This is a warning message.";
    const std::string infoMsg = "This is an informational message.";
    for (int i = 0; i < 60; i++) {
        if (i < 20) {
            Logger::Error() << errorMsg << "\n";
        } else if (i < 40) {
            Logger::Warn() << warnMsg << "\n";
        } else {
            Logger::Info() << infoMsg << "\n";
        }
    }

    Logger::flushOfstream();
    std::ifstream inFile(fname);
    std::string line;
    for (int i = 0; i < 60; i++) {
        ASSERT_FALSE(inFile.eof());
        std::getline(inFile, line);
        if (i < 20) {
            ASSERT_EQ(line.substr(20), "Error: " + errorMsg);
        } else if (i < 40) {
            ASSERT_EQ(line.substr(20), "Warning: " + warnMsg);
        } else {
            ASSERT_EQ(line.substr(20), "Info: " + infoMsg);
        }
    }
}

TEST_F(LogTest, setLogLevelShouldIgnoreInfoMessage) {
    const std::string fname = Logger::newLogfile();
    const std::string errorMsg = "This is an error message.";
    const std::string warnMsg = "This is a warning message.";
    const std::string infoMsg = "This is an informational message.";

    Logger::setLoglevel(LogType::Warn);

    Logger::Error() << errorMsg << "\n";
    Logger::Warn() << warnMsg << "\n";
    Logger::Info() << infoMsg << "\n";

    Logger::flushOfstream();
    std::ifstream inFile(fname);
    std::string line;

    std::getline(inFile, line);
    ASSERT_EQ(line.substr(20), "Error: " + errorMsg);
    std::getline(inFile, line);
    ASSERT_EQ(line.substr(20), "Warning: " + warnMsg);
    std::getline(inFile, line);
    ASSERT_EQ(line, line);
    ASSERT_TRUE(inFile.eof());
}



int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

