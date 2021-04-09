#include <iostream>
#include "log.h"
#include "ArtifactParser.h"
#include "Downloader.h"
#include "Writer.h"
#include <thread>
#include <memory>
#include <map>
#include <chrono>
#include "Writer.h"
#include <unistd.h>
#include <sys/reboot.h>

class bootenv_exception : public std::runtime_error {
public:
    explicit bootenv_exception(const char* message) : std::runtime_error(message) {}
};

class BootEnvWriter {
private:
    // adapted from: https://stackoverflow.com/questions/478898/how-do-i-execute-a-command-and-get-the-output-of-the-command-within-c-using-po
    std::string execCmd(const std::string& cmd) {
        std::array<char, 128> buffer{};
        std::string result;
        std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
        if (!pipe) {
            throw bootenv_exception("popen() failed.");
        }
        while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
            result += buffer.data();
        }
        return result;
    }

public:

    std::string readVar(const std::string& var) {
        std::ostringstream cmdStream;
        cmdStream << "fw_printenv " << var;
        return execCmd(cmdStream.str());
    }

    void writeVar(const std::string& var, const std::string& val) {
        std::ostringstream cmdStream;
        cmdStream << "fw_setenv " << var << " " << val;
        execCmd(cmdStream.str());
    }
};

class UpdateDriver {
private:

    std::unique_ptr<Downloader> client;
    std::string configPath;
    std::string serverAddr;
    std::string certificatePath;
    std::string rootCACertPath;
    std::string privateKeyPath;
    std::string publisherKeyPath;
    std::string logDir;
    int pollInterval;
    std::map<unsigned int, int> blacklist;
    LogType loglevel;
    BootEnvWriter envWriter;

    void rebootDevice() {
        sync();
        reboot(RB_AUTOBOOT);
    }

    void reset(const std::chrono::minutes& after, unsigned int updateId) {
        Logger::Warn() << "restarting poll in " << after.count() << " minutes\n";
        blacklist[updateId] = (int) time(nullptr);
        std::this_thread::sleep_for(after);
        startPoll();
    }

    void doInstall(const UpdateArtifact& artifact, unsigned int id) {
        std::string partB;
        try {
            partB = envWriter.readVar("ROOTFS_PART_B");
        } catch (bootenv_exception& e) {
            Logger::Error() << e.what() << "\n";
            reset(std::chrono::minutes(5), id);
        }
        ImageWriter writer{};
        // TODO: actually insall the image
    }

    void doParse(const std::vector<unsigned char>& artifactData,
                 const KeyServerResponse& keyResp, unsigned int id) {

        Logger::Info() << "decrypting aes-key\n";
        std::array<unsigned char, 16> keyPlain{};

        try {
            keyPlain = ArtifactCryptoHelper::decryptAESKey(privateKeyPath, keyResp.key);
        } catch (decryption_exception& e) {
            Logger::Error() << e.what() << "\n";
            Logger::Error() << "decryption of aes-key failed\n";
            reset(std::chrono::minutes(5), id);
        }

        ArtifactParser parser(publisherKeyPath, keyPlain, keyResp.iv);

        Logger::Info() << "decrypting artifact\n";
        std::vector<unsigned char> artifactPlain;

        try {
            artifactPlain = parser.Decrypt(artifactData);
        } catch (decryption_exception& e) {
            Logger::Error() << e.what() << "\n";
            Logger::Error() << "decryption of artifact failed\n";
            reset(std::chrono::minutes(5), id);
        }

        if (artifactPlain.empty()) {
            Logger::Error() << "artifact ciphertext could not be authenticated\n";
            reset(std::chrono::minutes(5), id);
        }

        Logger::Info() << "verifying artifact signature\n";

        bool ok = false;
        try {
            ok = parser.Verify(artifactPlain);
        } catch (verify_signature_exception& e) {
            Logger::Error() << e.what() << "\n";
            Logger::Error() << "verifying of artifact failed\n";
            reset(std::chrono::minutes(5), id);
        }

        if (!ok) {
            Logger::Error() << "artifact could not be verified\n";
            reset(std::chrono::minutes(5), id);
        }

        Logger::Info() << "successfully verified artifact\n";
        Logger::Info() << "parsing artifact\n";

        UpdateArtifact artifact{};

        try {
            artifact = parser.Parse(artifactPlain);
        } catch (parse_exception& e) {
            Logger::Error() << e.what() << "\n";
            Logger::Error() << "parsing of artifact failed\n";
            reset(std::chrono::minutes(5), id);
        }

        std::string asString{artifact.firmwarePayload.begin(), artifact.firmwarePayload.end()};
        std::cout << asString << "\n";
    }

    /*
 * Load all necessary parameters;
 * Should use a configuration file but remains hardcoded for now
 */
    void loadConfiguration() {

        // HardwareUUID
        // Sequencenumber

        serverAddr = "https://localhost:8090";
        certificatePath = "/usr/UpdateCrypto/client/clientCert.pem";
        privateKeyPath = "/usr/UpdateCrypto/client/clientPrivkey.pem";
        rootCACertPath = "/usr/UpdateCrypto/rootCA/caCert.pem";
        publisherKeyPath = "/usr/UpdateCrypto/publisher/publisherPubkey.pem";
        logDir = "/usr/UpdateLogs";
        loglevel = LogType::Info;
    }



    void startFetch(unsigned id) {
        Logger::Info() << "fetching decryption key\n";
        KeyServerResponse keyResp{};
        try {
            keyResp = client->FetchKey(id);
        } catch (fetch_exception& e) {
            Logger::Error() << e.what() << "\n";
            Logger::Error() << "fetching decryption key failed\n";
            reset(std::chrono::minutes(5), id);
        }

        if (keyResp.httpCode != 200) {
            Logger::Error() << "fetching decryption key failed with http-response code " << keyResp.httpCode << "\n";
            reset(std::chrono::minutes(5), id);
        }

        Logger::Info() << "fetching artifact\n";

        ArtifactServerResponse artifactResp{};

        try {
            artifactResp = client->FetchArtifact(id);
        } catch (fetch_exception& e) {
            Logger::Error() << e.what() << "\n";
            Logger::Error() << "fetching artifact failed\n";
            reset(std::chrono::minutes(5), id);
        }

        if (keyResp.httpCode != 200) {
            Logger::Error() << "fetching artifact failed with http-response code " << keyResp.httpCode << "\n";
            reset(std::chrono::minutes(5), id);
        }
        Logger::Info() << "successfully fetched key and artifact\n";

        doParse(artifactResp.artifact, keyResp, id);
    }


public:

    void init() {
        loadConfiguration();
        Logger::setLoglevel(loglevel);
        Logger::setLogdir(logDir);
        Logger::Info().setFlushThreshold(0);
        Logger::Error().setFlushThreshold(0);
        Logger::setStdout(true);
        Downloader cl(serverAddr, std::chrono::milliseconds(5000), rootCACertPath,
                      certificatePath, privateKeyPath, 3);

        client = std::make_unique<Downloader>(cl);
    }

    explicit UpdateDriver(std::string configPath) noexcept: configPath(std::move(configPath)), client{nullptr},
                                                            blacklist{},
                                                            envWriter{} {}


    void startPoll() {

        auto availableUpdates = client->DoPoll();

        // Choose the latest, non-blacklisted Update
        unsigned int* newest = nullptr;
        for (auto upd : availableUpdates) {
            if (blacklist.find(upd) == blacklist.end()) {
                newest = &upd;
            } else {
                // TODO: Check how much time has passed
            }
        }

        if (newest == nullptr) {
            std::this_thread::sleep_for((std::chrono::minutes(5)));
            startPoll();
        }

        Logger::newLogfile();
        Logger::Info() << "initializing update with id=" << *newest << "\n";

        startFetch(*newest);
    }
};

int main() {
    UpdateDriver driver("");

    driver.init();
    driver.startPoll();
}
