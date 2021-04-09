#include "ArtifactParser.h"


std::vector<unsigned char> ArtifactParser::Decrypt(const std::vector<unsigned char>& artifact) {
    return ArtifactCryptoHelper::AESGCMDecrypt(artifact, decryptionKey, iv);
}

bool ArtifactParser::Verify(const std::vector<unsigned char>& artifactPlaintext) {
    return ArtifactCryptoHelper::VerifyArtifactSignature(verifyKeyPath, artifactPlaintext);
}

ushort ArtifactParser::ParseURILength(const unsigned char* uriLength) {
    return *(static_cast<const ushort*>(static_cast<const void*>(uriLength)));
}

ulong ArtifactParser::ParseSequenceNumber(const unsigned char* sequenceNumber) {
    return *(static_cast<const ulong*>(static_cast<const void*>(sequenceNumber)));
}

UpdateArtifact ArtifactParser::Parse(const std::vector<unsigned char>& verifiedPlaintext) {

    if (verifiedPlaintext.size() < URI_OFFSET) {
        throw parse_exception("malformed artifact binary");
    }

    UpdateArtifact artifact;
    std::copy(verifiedPlaintext.begin() + SIGNATURE_OFFSET, verifiedPlaintext.begin() + SEQUENCE_NUMBER_OFFSET,
              artifact.rsaSignature.begin());

    artifact.header.sequenceNumber = ParseSequenceNumber(verifiedPlaintext.data() + SEQUENCE_NUMBER_OFFSET);

    std::copy(verifiedPlaintext.begin() + HARDWARE_UUID_OFFSET, verifiedPlaintext.begin() + URI_LENGTH_OFFSET,
              artifact.header.hardwareUUID.begin());

    artifact.header.uriLength = ParseURILength(verifiedPlaintext.data() + URI_LENGTH_OFFSET);

    if (verifiedPlaintext.size() < URI_OFFSET + artifact.header.uriLength) {
        throw parse_exception("malformed artifact binary");
    }

    artifact.header.uri = std::string(verifiedPlaintext.begin() + URI_OFFSET,
                                      verifiedPlaintext.begin() + URI_OFFSET + artifact.header.uriLength);

    artifact.firmwarePayload.resize(verifiedPlaintext.size() - (URI_OFFSET + artifact.header.uriLength));


    std::copy(verifiedPlaintext.begin() + URI_OFFSET + artifact.header.uriLength, verifiedPlaintext.end(),
              artifact.firmwarePayload.begin());

    return artifact;
}

ArtifactParser::ArtifactParser(std::string verifyKeyPath,
                               const std::array<unsigned char, 16>& decryptionKey,
                               const std::array<unsigned char, 12>& iv) noexcept:
        verifyKeyPath(std::move(verifyKeyPath)),
        decryptionKey(decryptionKey),
        iv(iv) {}

