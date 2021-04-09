package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
)

type PrepareUpdateData struct {
	Keys      []DecryptionKeyCiphertext `json:"keys"`
	Available int64                     `json:"available"`
}

type DecryptionKeyCiphertext struct {
	SAN string    `json:"san"`
	CT  [256]byte `json:"ct"`
	IV  [12]byte  `json:"iv"`
}

type DaysJSONStruct struct {
	AvailableAt string `json:"days"`
}

// Encrypts a given AES-Key with all RSA-Keys in the specified
// directory and stores them in a map, where key is the cert.
// SAN and value is the ciphertext of the AES-Key
func EncryptWithDirectory(certPath string, aesKeyPath string, ivPath string) ([]DecryptionKeyCiphertext, error) {
	certMap := make(map[string]*rsa.PublicKey)

	err := filepath.Walk(certPath, func(path string, info os.FileInfo, err error) error {

		certBin, err := ioutil.ReadFile(path)
		block, _ := pem.Decode(certBin)
		if block != nil {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				certMap[cert.DNSNames[0]] = cert.PublicKey.(*rsa.PublicKey)
				fmt.Println(cert.DNSNames[0])
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	aesKey, err := ioutil.ReadFile(aesKeyPath)
	iv, err := ioutil.ReadFile(ivPath)

	if err != nil {
		return nil, err
	}
	var decryptionKeyCiphertexts []DecryptionKeyCiphertext

	var ciphertextBuff [256]byte
	var ivBuff [12]byte
	copy(ivBuff[:], iv)

	for name, pubKey := range certMap {
		//hash := sha512.New()
		//ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pubKey, aesKey, nil)
		ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, aesKey)
		if err != nil {
			return nil, err
		}
		copy(ciphertextBuff[:], ciphertext)

		decryptionKeyCiphertexts = append(decryptionKeyCiphertexts,
			DecryptionKeyCiphertext{SAN: name, CT: ciphertextBuff, IV: ivBuff})
	}

	return decryptionKeyCiphertexts, nil
}

func SaveCiphertexts(dir string, ciphertexts []DecryptionKeyCiphertext) error {
	for _, ciphertext := range ciphertexts {
		path := fmt.Sprintf("%s/%s", dir, ciphertext.SAN)
		err := ioutil.WriteFile(path, ciphertext.CT[:], 0777)
		if err != nil {
			return err
		}
	}
	return nil
}

type PublisherClient struct {
	httpClient *http.Client
}

func (client PublisherClient) UploadArtifact(updateId uint32, artifactPath string) error {
	println("Sending id: ", updateId, "\n")
	artifact, err := ioutil.ReadFile(artifactPath)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", "https://localhost:8090/uploadArtifact", bytes.NewBuffer(artifact))
	q := req.URL.Query()
	q.Add("updateId", fmt.Sprint(updateId))
	req.URL.RawQuery = q.Encode()
	resp, err := client.httpClient.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusNoContent {
		body, err := ioutil.ReadAll(resp.Body)
		if body != nil && err != nil {
			fmt.Println(string(body))
		}
		return errors.New(fmt.Sprintf("request might have failed, returned Code %d", resp.StatusCode))
	}
	return nil
}

func (client PublisherClient) SendPrepareUpdateMessage(ciphertexts []DecryptionKeyCiphertext, available int64) (uint32, error) {

	data := PrepareUpdateData{Keys: ciphertexts, Available: available}

	strB, err := json.Marshal(data)
	if err != nil {
		return 0, err
	}

	fmt.Println(string(strB))
	req, err := http.NewRequest("POST", "https://localhost:8090/prepareUpdate", bytes.NewBuffer(strB))
	if err != nil {
		return 0, err
	}
	response, err := client.httpClient.Do(req)
	if response == nil {
		return 0, err
	}
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return 0, err
	}
	updateId, err := strconv.ParseUint(string(body), 10, 32)
	fmt.Println("Update-Id=", updateId)
	return uint32(updateId), err
}

func CreateHttpsClient() (*http.Client, error) {
	caCert, err := ioutil.ReadFile("ca-crt.pem")
	if err != nil {
		return nil, err
	}

	cert, err := tls.LoadX509KeyPair("publisher.crt", "publisher.pem")
	if err != nil {
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caCertPool,
				Certificates: []tls.Certificate{cert},
			},
		},
	}
	return client, nil
}

func main() {

	artifactFlag := flag.String("art", "", "Specify URI of FW-PayloadPath")
	ivFlag := flag.String("iv", "", "Specify path to iv")
	keyFlag := flag.String("key", "", "Specify path ot aes-key")
	certsFlag := flag.String("certs", "", "Specify path to client-cert-dirs")
	availableFlag := flag.String("available", "", "Specify the time of availability of the update")

	flag.Parse()

	client, err := CreateHttpsClient()
	if err != nil {
		log.Fatal(err)
	}
	pubClient := PublisherClient{client}
	r, err := client.Get("https://localhost:8090/whatsNew")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(r.Body)

	m, err := EncryptWithDirectory(*certsFlag, *keyFlag, *ivFlag)
	if err != nil {
		log.Fatal(err)
	}
	av, err := strconv.ParseInt(*availableFlag, 10, 64)
	if err != nil {
		panic(err)
	}
	updateId, err := pubClient.SendPrepareUpdateMessage(m, av)
	fmt.Println(updateId)

	err = pubClient.UploadArtifact(updateId, *artifactFlag)
	err = SaveCiphertexts("aesCiphertexts", m)
	if err != nil {
		log.Fatal(err)
	}
}
