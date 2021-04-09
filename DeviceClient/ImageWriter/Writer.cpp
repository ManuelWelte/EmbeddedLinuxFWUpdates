#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <unistd.h>

#include <exception>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

#include "Writer.h"

BlockdeviceException::BlockdeviceException(const char* message)
    : std::runtime_error(message) {}

ImageFileException::ImageFileException(const char* message)
    : std::runtime_error(message) {}

ImageWriter::~ImageWriter() noexcept {
    try {
        closeDevice();
    } catch (BlockdeviceException& e) {
        std::cout << e.what() << std::endl;
    }
}

ImageWriter::ImageWriter(const std::string& devicePath)
    : devicePath_{devicePath}, blockDevice_{-1}, blockDevSize_{0} {
    try {
        openBlockDevice();
        this->blockDevSize_ = obtainBlockDeviceSize();
    } catch (BlockdeviceException& e) {
        std::string errorMsg = std::string("init. failed, reason: ") + e.what();
        throw(BlockdeviceException(errorMsg.c_str()));
    }
}

ImageWriter::ImageWriter()
    : devicePath_{}, blockDevice_{-1}, blockDevSize_{0} {}

ImageWriter::ImageWriter(ImageWriter&& other) noexcept
    : devicePath_{std::move(other.devicePath_)},
      blockDevice_{std::move(other.blockDevice_)},
      blockDevSize_{std::move(other.blockDevSize_)} {
    other.blockDevice_ = -1;
}

ImageWriter& ImageWriter::operator=(ImageWriter&& other) noexcept {
    try {
        closeBlockDevice(this->blockDevice_);
    } catch (BlockdeviceException& e) {
        std::cout << e.what() << std::endl;
    }
    this->devicePath_ = std::move(other.devicePath_);
    this->blockDevice_ = std::move(other.blockDevice_);
    this->blockDevSize_ = std::move(other.blockDevSize_);
    other.blockDevSize_ = -1;
    return *this;
}

unsigned long ImageWriter::getBlockDeviceSize() const { return blockDevSize_; }

std::string ImageWriter::getDevicePath() const { return devicePath_; }

bool ImageWriter::blockDeviceIsOpen() const { return blockDevice_ != -1; }

void ImageWriter::openDevice(const std::string& devicePath) {
    int oldBlockDevice = this->blockDevice_;
    std::string oldDevicePath = this->devicePath_;
    this->devicePath_ = devicePath;
    try {
        openBlockDevice();
        this->blockDevSize_ = obtainBlockDeviceSize();
    } catch (BlockdeviceException& e) {
        this->devicePath_ = oldDevicePath;
        this->blockDevice_ = oldBlockDevice;
        std::string errorMsg = std::string("init. failed, reason: ") + e.what();
        throw BlockdeviceException(errorMsg.c_str());
    }
    try {
        closeBlockDevice(oldBlockDevice);
    } catch (BlockdeviceException& e) {
        std::cout << "Could not close old blockdevice handle." << std::endl;
    }
}

ssize_t ImageWriter::writeImage(const std::string& imagePath,
                                ssize_t bufferSize) const {
    if (!blockDeviceIsOpen()) {
        return 0;
    }
    std::ifstream imageStream = obtainImageStream(imagePath);
    std::vector<char> buffer(bufferSize, 0);
    imageStream.seekg(0, std::ios::beg);
    if (imageStream.fail()) {
        throw ImageFileException(
            "Aborting write, reason: Unable to seekg to beginning of image "
            "file.");
    }
    if (lseek(blockDevice_, 0, SEEK_SET) == -1) {
        throw BlockdeviceException(
            "aborting write, reason: Unable to lseek to beginning of "
            "blockdevice file");
    }
    ssize_t written = 0;
    while (!imageStream.eof()) {
        imageStream.read(&buffer.front(), bufferSize);
        try {
            written += writeBuffer(buffer, imageStream.gcount());
        } catch (BlockdeviceException& e) {
            std::string errorMsg =
                std::string("Aborting write, reason: ") + e.what();
            throw BlockdeviceException(errorMsg.c_str());
        }
    }
    return written;
}

void ImageWriter::openBlockDevice() {
    std::string mntPoint = checkIfMounted(this->devicePath_);
    if (!mntPoint.empty()) {
        std::cout << "Device is mounted. Trying to unmount." << std::endl;
        if (umount2(mntPoint.c_str(), 0) == -1) {
            const std::string errorMsg =
                std::string("Unable to unmount device: ") + strerror(errno);
            throw BlockdeviceException(errorMsg.c_str());
        }
    };
    this->blockDevice_ = open(this->devicePath_.c_str(), O_RDWR | O_EXCL);
    if (this->blockDevice_ == -1) {
        const std::string errorMsg = std::string("Unable to open device ") +
                                     this->devicePath_ +
                                     " ,reason: " + strerror(errno);
        throw BlockdeviceException(errorMsg.c_str());
    }
}

std::string ImageWriter::checkIfMounted(const std::string& devicePath) const {
    std::ifstream mountsFile("/proc/self/mounts");
    if (mountsFile.is_open()) {
        std::string line;
        while (getline(mountsFile, line)) {
            std::istringstream wordStream(line);
            std::string word;
            wordStream >> word;
            if (word == devicePath) {
                wordStream >> word;
                return word;
            }
        }
    } else {
        throw BlockdeviceException("Unable to open /proc/self/mounts.");
    }
    return "";
}

void ImageWriter::closeBlockDevice(int blockDevice) {
    if (blockDevice == -1) {
        return;
    }
    if (close(blockDevice) == -1) {
        const std::string errorMsg =
            std::string("Unable to close device: ") + strerror(errno);
        throw BlockdeviceException(errorMsg.c_str());
    }
}

void ImageWriter::closeDevice() {
    closeBlockDevice(blockDevice_);
    blockDevice_ = -1;
    blockDevSize_ = 0;
    devicePath_ = "";
}

unsigned long ImageWriter::obtainBlockDeviceSize() const {
    if (!blockDeviceIsOpen()) {
        return 0;
    }
    unsigned long blockDevSize = 0;
    if (ioctl(blockDevice_, BLKGETSIZE64, &blockDevSize) == -1) {
        const std::string errorMsg =
            std::string("Unable to retreive device size: ") + strerror(errno);
        throw BlockdeviceException(errorMsg.c_str());
    }
    return blockDevSize;
}

size_t ImageWriter::writeBuffer(const std::vector<char>& buffer,
                                size_t nBytes) const {
    if (!blockDeviceIsOpen()) {
        return 0;
    }
    ssize_t written = write(blockDevice_, &buffer.front(), nBytes);
    if (written == -1) {
        const std::string errorMsg =
            std::string("Unable to write buffer to device: ") + strerror(errno);
        throw BlockdeviceException(errorMsg.c_str());
    }
    return written;
}

std::ifstream ImageWriter::obtainImageStream(
    const std::string& imagePath) const {
    std::ifstream imageFile(imagePath, std::ios::binary | std::ios::in);
    if (!imageFile.is_open()) {
        throw ImageFileException("Unable to open image file.");
    }
    return imageFile;
}
