//
// Created by mwelte on 01.04.21.
//

#ifndef UPDATECLIENT_ARTIFACTPARSER_H
#define UPDATECLIENT_ARTIFACTPARSER_H

#include <iostream>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <vector>
#include <fstream>
#include <cstring>
#include <cerrno>
#include <array>
#include <algorithm>
#include "ArtifactCryptoHelper.h"
#include <exception>

class parse_exception : public std::runtime_error {
public:
    explicit parse_exception(const char* message) : std::runtime_error(message) {}
};

const int SIGNATURE_OFFSET = 0;
const int SEQUENCE_NUMBER_OFFSET = 256;
const int HARDWARE_UUID_OFFSET = 264;
const int URI_LENGTH_OFFSET = 280;
const int URI_OFFSET = 282;

struct ArtifactHeader {
    ulong sequenceNumber;
    std::array<unsigned char, 16> hardwareUUID;
    ushort uriLength;
    std::string uri;
};

struct UpdateArtifact {
    std::array<unsigned char, 256> rsaSignature;
    ArtifactHeader header;
    std::vector<unsigned char> firmwarePayload;

};

class ArtifactParser {
private:
    std::array<unsigned char, 16> decryptionKey{};
    std::string verifyKeyPath;
    std::array<unsigned char, 12> iv{};


    ushort ParseURILength(const unsigned char* uriLength);

    ulong ParseSequenceNumber(const unsigned char* sequenceNumber);

public:

    std::vector<unsigned char> Decrypt(const std::vector<unsigned char>& artifact);

    bool Verify(const std::vector<unsigned char>& artifactPlaintext);

    UpdateArtifact Parse(const std::vector<unsigned char>& verifiedPlaintext);

    explicit ArtifactParser(std::string verifyKeyPath,
                            const std::array<unsigned char, 16>& decryptionKey,
                            const std::array<unsigned char, 12>& iv) noexcept;

};


#endif //UPDATECLIENT_ARTIFACTPARSER_H
