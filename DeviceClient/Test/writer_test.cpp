#include "Writer.h"

#include <fstream>
#include <sstream>
#include <vector>

#include "gtest/gtest.h"

struct ImageFile {
    ImageFile(const std::string& imagePath, int megabytes)
        : imagePath{imagePath}, megabytes{megabytes} {}
    std::string imagePath;
    int megabytes;
};

struct LoopDevice {
    LoopDevice(const std::string& deviceName, ImageFile image)
        : deviceName(deviceName), image(image) {}
    std::string deviceName;
    ImageFile image;
};

class ImageWriterTest : public ::testing::Test {
   protected:
    // Source:
    // https://stackoverflow.com/questions/478898/how-do-i-execute-a-command-and-get-the-output-of-the-command-within-c-using-po
    static std::string execCmd(const char* cmd) {
        std::array<char, 128> buffer;
        std::string result;
        std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
        if (!pipe) {
            throw std::runtime_error("popen() failed.");
        }
        while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
            result += buffer.data();
        }
        return result;
    }

    static bool createEmptyImage(const char* outFilePath, int megabytes) {
        // Don't accidentally overwrite an important file.
        std::string out(outFilePath);
        if (out.find("loop_device_file_for_flash_writer_test_") ==
            std::string::npos) {
            return false;
        };
        std::ostringstream cmdStream;
        cmdStream << "dd if=/dev/zero "
                  << "of=" << outFilePath << " bs=" << megabytes << "M count=1";
        std::string result = execCmd(cmdStream.str().c_str());
        return true;
    }

    static std::string deleteAllImageFiles(
        const std::vector<ImageFile>& images) {
        std::string result;
        std::string subResult;
        for (auto& image : images) {
            if (image.imagePath.find(
                    "loop_device_file_for_flash_writer_test_") !=
                std::string::npos) {
                std::ostringstream cmdStream;
                cmdStream << "rm " << image.imagePath;
                subResult = execCmd(cmdStream.str().c_str());
                if (!subResult.empty()) {
                    result += "\n" + subResult;
                }
            }
        }
        return result;
    }

    static std::string setUpLoopDevice(const char* devicefilePath) {
        std::ostringstream cmdStream;
        cmdStream << "losetup -fP " << devicefilePath;
        std::string result = execCmd(cmdStream.str().c_str());
        return result;
    }

    static std::string detachLoopDevice(const char* deviceFilePath) {
        std::ostringstream cmdStream;
        cmdStream << "losetup -d " << deviceFilePath;
        std::string result = execCmd(cmdStream.str().c_str());
        return result;
    }

    static std::string getLoopDeviceName(const char* imageFilePath) {
        std::ostringstream cmdStream;
        cmdStream << "losetup --list | grep " << imageFilePath;
        std::string result = execCmd(cmdStream.str().c_str());
        std::istringstream wordStream(result);
        std::string deviceName;
        wordStream >> deviceName;
        return deviceName;
    }

    static std::string detachAllLoopDevices(
        const std::vector<LoopDevice>& devices) {
        std::string result;
        std::string subresult;
        for (auto& device : devices) {
            subresult = detachLoopDevice(device.deviceName.c_str());
            if (subresult != "") {
                result += "\n" + subresult;
            }
        }
        return result;
    }

    static std::string mountDevice(const std::string& device,
                                   const std::string& mntPoint) {
        std::ostringstream cmdStrm;
        cmdStrm << "mount " << device << " " << mntPoint;
        std::string cmd = cmdStrm.str();
        std::string result = execCmd(cmd.c_str());
        return result;
    }

    static std::string unmountDevice(const std::string& device) {
        std::ostringstream cmdStrm;
        cmdStrm << "umount " << device;
        std::string result = execCmd(cmdStrm.str().c_str());
        return result;
    }

    static const std::vector<ImageFile> loopImageFiles;
    static std::vector<LoopDevice> loopDevices;

    static const std::vector<std::string> rootFSFiles;

   public:
    static void SetUpTestSuite() {
        if (getuid()) {
            std::cout << "Please run these tests as sudo." << std::endl;
            exit(EXIT_FAILURE);
        }

        std::string res;
        std::string deviceName;
        for (auto& image : loopImageFiles) {
            bool succ =
                createEmptyImage(image.imagePath.c_str(), image.megabytes);
            setUpLoopDevice(image.imagePath.c_str());
            deviceName = getLoopDeviceName(image.imagePath.c_str());
            if (!succ || deviceName.empty()) {
                std::cout << "Failed to setup loopdevice: " << res << std::endl;
                detachAllLoopDevices(loopDevices);
                std::vector<ImageFile> existingImages;
                existingImages.reserve(loopDevices.size());
                for (auto& device : loopDevices) {
                    existingImages.push_back(device.image);
                }
                deleteAllImageFiles(existingImages);
                exit(EXIT_FAILURE);
            }
            loopDevices.push_back(LoopDevice{deviceName, image});
        }
    }

    static void TearDownTestSuite() {
        std::string result;
        std::string subResult;
        subResult = detachAllLoopDevices(loopDevices);
        if (!subResult.empty()) {
            result += "\n" + subResult;
        }
        subResult = deleteAllImageFiles(loopImageFiles);
        if (!subResult.empty()) {
            result += "\n" + subResult;
        }
        if (!result.empty()) {
            std::cout << result;
        }
    }
};

std::vector<LoopDevice> ImageWriterTest::loopDevices;

const std::vector<ImageFile> ImageWriterTest::loopImageFiles{
    ImageFile{"virtual_device/loop_device_file_for_flash_writer_test_300MB.img",
              300},
    ImageFile{"virtual_device/loop_device_file_for_flash_writer_test_5MB.img",
              5}};

const std::vector<std::string> ImageWriterTest::rootFSFiles{
    "../images/image.rootfs.ext3",
    "../images/core-image-base-raspberrypi4.ext3"};

TEST_F(ImageWriterTest, constructorTestValidDevice) {
    try {
        ImageWriter writer{loopDevices[0].deviceName};
        ASSERT_TRUE(writer.blockDeviceIsOpen());
        ASSERT_EQ(writer.getDevicePath(), loopDevices[0].deviceName);
        ASSERT_EQ(writer.getBlockDeviceSize(), 300 * 1024 * 1024);

    } catch (BlockdeviceException& e) {
        FAIL();
    }
}

TEST_F(ImageWriterTest, constructorTestInvalidDevice) {
    ASSERT_THROW(ImageWriter("/dev/nonsense"), BlockdeviceException);
}

TEST_F(ImageWriterTest, openBlockDeviceTestDefaultCase) {
    ImageWriter writer;
    try {
        writer.openDevice(loopDevices[0].deviceName);
    } catch (BlockdeviceException& e) {
        std::cout << e.what() << std::endl;
        FAIL();
    }
    ASSERT_TRUE(writer.blockDeviceIsOpen());
    ASSERT_EQ(writer.getDevicePath(), loopDevices[0].deviceName);
    ASSERT_TRUE(writer.getBlockDeviceSize() > 0);
}

TEST_F(ImageWriterTest, openBlockDeviceTestInvalidDevice) {
    ImageWriter writer;
    ASSERT_THROW(writer.openDevice("/dev/inval0"), BlockdeviceException);

    ASSERT_FALSE(writer.blockDeviceIsOpen());
    ASSERT_EQ(writer.getBlockDeviceSize(), 0);
    ASSERT_EQ(writer.getDevicePath(), "");
}

TEST_F(ImageWriterTest, openBlockDeviceTestOpenOtherValidDevice) {
    ImageWriter writer;
    writer.openDevice(loopDevices[0].deviceName);
    try {
        writer.openDevice(loopDevices[1].deviceName);
    } catch (BlockdeviceException& e) {
        std::cout << e.what() << std::endl;
        FAIL();
    }
    ASSERT_TRUE(writer.blockDeviceIsOpen());
    ASSERT_EQ(writer.getDevicePath(), loopDevices[1].deviceName);
}

TEST_F(ImageWriterTest, openBlockDeviceTestOpenOtherInvalidDevice) {
    ImageWriter writer;
    writer.openDevice(loopDevices[0].deviceName);
    unsigned long oldSize = writer.getBlockDeviceSize();
    try {
        writer.openDevice("/dev/inval0");
    } catch (BlockdeviceException& e) {
        ASSERT_TRUE(writer.blockDeviceIsOpen());
        ASSERT_EQ(writer.getDevicePath(), loopDevices[0].deviceName);
        ASSERT_EQ(writer.getBlockDeviceSize(), oldSize);
    }
}

TEST_F(ImageWriterTest, openBlockDeviceTestValidateExclusiveAccess) {
    // Enter scope
    {
        ImageWriter writer;
        writer.openDevice(loopDevices[0].deviceName);
        ImageWriter writer2;
        // writer already has exclusive access to blockdevice
        ASSERT_THROW(writer2.openDevice(loopDevices[0].deviceName),
                     BlockdeviceException);
        // blockdevice becomes available again
        writer.closeDevice();
        try {
            writer2.openDevice(loopDevices[0].deviceName);
        } catch (BlockdeviceException& e) {
            FAIL();
        }
    }
    ImageWriter writer3;
    // writer2 went out of scope, destructor should have freed the
    // blockdevice
    try {
        writer3.openDevice(loopDevices[0].deviceName);
    } catch (BlockdeviceException& e) {
        FAIL();
    }
}

TEST_F(ImageWriterTest, closeBlockDeviceTestDefaultCase) {
    ImageWriter writer;
    writer.openDevice(loopDevices[0].deviceName);
    ASSERT_TRUE(writer.blockDeviceIsOpen());
    try {
        writer.closeDevice();
    } catch (BlockdeviceException& e) {
        std::cout << e.what() << std::endl;
        FAIL();
    }
    ASSERT_FALSE(writer.blockDeviceIsOpen());
    ASSERT_EQ(writer.getBlockDeviceSize(), 0);
    ASSERT_EQ(writer.getDevicePath(), "");
}

TEST_F(ImageWriterTest, closeBlockDeviceTestOnAlreadyClosedDevice) {
    ImageWriter writer;
    try {
        writer.closeDevice();
    } catch (BlockdeviceException& e) {
        std::cout << e.what() << std::endl;
        FAIL();
    }
    ImageWriter writer2;
    writer2.openDevice(loopDevices[0].deviceName);
    writer2.closeDevice();
    try {
        writer2.closeDevice();
    } catch (BlockdeviceException& e) {
        std::cout << e.what() << std::endl;
        FAIL();
    }
}

TEST_F(ImageWriterTest, getBlockDeviceSizeDefaultCase) {
    ImageWriter writer;

    ASSERT_EQ(writer.getBlockDeviceSize(), 0);
    writer.openDevice(loopDevices[0].deviceName);
    ASSERT_EQ(writer.getBlockDeviceSize(), 300 * 1024 * 1024);
    writer.openDevice(loopDevices[1].deviceName);
    ASSERT_EQ(writer.getBlockDeviceSize(), 5 * 1024 * 1024);
    writer.closeDevice();
    ASSERT_EQ(writer.getBlockDeviceSize(), 0);
}

TEST_F(ImageWriterTest, getBlockDeviceSizeTestAfterOpeningFailure) {
    ImageWriter writer;
    ASSERT_THROW(writer.openDevice("/dev/nonsense"), BlockdeviceException);

    ASSERT_EQ(writer.getBlockDeviceSize(), 0);
    writer.openDevice(loopDevices[0].deviceName);
    ASSERT_EQ(writer.getBlockDeviceSize(), 300 * 1024 * 1024);

    ImageWriter writer2;
    writer2.openDevice(loopDevices[1].deviceName);
    ASSERT_EQ(writer2.getBlockDeviceSize(), 5 * 1024 * 1024);

    ASSERT_THROW(writer2.openDevice("/dev/nonsense"),
                 BlockdeviceException);
    // Pre-Exception state should have been restored.
    ASSERT_EQ(writer2.getBlockDeviceSize(), 5 * 1024 * 1024);
}

TEST_F(ImageWriterTest, writeImageFileTestValidRootFS) {
    ImageWriter writer{loopDevices[0].deviceName};
    try {
        ssize_t written = writer.writeImage(rootFSFiles[1], 1024);
        ASSERT_EQ(written, 168 * 1024 * 1024);
    } catch (BlockdeviceException& e) {
        FAIL();
    } catch (ImageFileException& e) {
        FAIL();
    }
    std::string devicePath = writer.getDevicePath();
    writer.closeDevice();
    std::string res = mountDevice(devicePath, "/mnt");
    if (!res.empty()) {
        std::cout << res << std::endl;
    }
    // Check if kernel-image exists
    std::ifstream kernelFile{"/mnt/boot/kernelimg/uImage"};
    bool exists = kernelFile.good();
    kernelFile.close();
    res = unmountDevice(devicePath);
    if (!res.empty()) {
        std::cout << res << std::endl;
    }
    ASSERT_TRUE(exists);
}


int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
