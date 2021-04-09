#include <exception>
#include <iostream>
#include <vector>

#ifndef FLASH_WRITER
#define FLASH_WRITER

class BlockdeviceException : public std::runtime_error {
   public:
    BlockdeviceException(const char* message);
};

class ImageFileException : public std::runtime_error {
   public:
    ImageFileException(const char* message);
};

class ImageWriter {
    friend class FlashWriterTest;

   public:
    ~ImageWriter() noexcept;

    ImageWriter(const std::string& devicePath);

    ImageWriter();

    ImageWriter(ImageWriter& other) = delete;

    ImageWriter& operator=(ImageWriter& other) = delete;

    ImageWriter(ImageWriter&& other) noexcept;

    ImageWriter& operator=(ImageWriter&& other) noexcept;

    unsigned long getBlockDeviceSize() const;

    std::string getDevicePath() const;

    bool blockDeviceIsOpen() const;

    void openDevice(const std::string& devicePath);

    void closeDevice();

    ssize_t writeImage(const std::string& imagePath,
                       ssize_t bufferSize) const;

   private:
    std::string devicePath_;
    int blockDevice_;
    long blockDevSize_;

    void openBlockDevice();

    std::string checkIfMounted(const std::string& devicePath) const;

    void closeBlockDevice(int blockDevice);

    unsigned long obtainBlockDeviceSize() const;

    size_t writeBuffer(const std::vector<char>& buffer, size_t nBytes) const;

    std::ifstream obtainImageStream(const std::string& imagePath) const;
};
#endif