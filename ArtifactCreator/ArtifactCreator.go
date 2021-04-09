package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strconv"
)

type UpdateArtifact struct {
	Header      UpdateHeader
	PayloadPath string
}

func SignSHA256Digest(keyPath string, hashVal [32]byte) (*[256]byte, error) {
	signer, err := NewRSASigner(keyPath)
	if err != nil {
		return nil, err
	}
	sig, err := signer.SignSHA256Digest(hashVal)
	return sig, err
}

// Encrypt Update-Artifact symmetrically
func (artifact *UpdateArtifact) EncryptAndSerialize(AESKeyPath string, outDirPath string) ([]byte, error) {
	fmt.Println("Serializing")

	cipherText, nonce, key, err := EncryptArtifact(AESKeyPath, *artifact)
	if err != nil {
		return nil, err
	}

	// Todo: Find out appropriate permissions
	if _, err := os.Stat(outDirPath); os.IsNotExist(err) {
		err = os.Mkdir(outDirPath, os.ModePerm)
		if err != nil {
			return nil, err
		}
	}

	artifactOut := fmt.Sprintf("%s/artifact.upd", outDirPath)
	ivOut := fmt.Sprintf("%s/iv", outDirPath)
	keyOut := fmt.Sprintf("%s/key", outDirPath)
	fmt.Println(artifactOut)

	err = ioutil.WriteFile(artifactOut, cipherText, os.ModePerm)
	err = ioutil.WriteFile(ivOut, nonce, os.ModePerm)
	err = ioutil.WriteFile(keyOut, key, os.ModePerm)

	if err!= nil {
		fmt.Println(err)
	}

	return cipherText, err
}

type UpdateHeader struct {
	// Sqn. needs to be managed by the publisher
	SequenceNumber [8]byte
	HardwareUUID   [16]byte
	URILength      [2]byte
	URIData        []byte

	Signature [256]byte
}

func (artifact *UpdateArtifact) AddRSASignature(digest [32]byte, keyPath string) error {
	sig, err := SignSHA256Digest(keyPath, digest)
	if err != nil {
		return err
	}
	artifact.Header.Signature = *sig
	return nil
}

func (header *UpdateHeader) CalcSHA256ArtifactDigest(file *os.File, imageChunkSize uint32) (*[32]byte, error) {
	hashbuilder := sha256.New()

	hashbuilder.Write(header.SequenceNumber[:])
	hashbuilder.Write(header.HardwareUUID[:])
	hashbuilder.Write(header.URILength[:])
	hashbuilder.Write(header.URIData)

	buffer := make([]byte, imageChunkSize)
	reader := bufio.NewReader(file)
	for {
		read, err := reader.Read(buffer)
		if err != nil {
			if err == io.EOF {
				break
			} else {
				return nil, err
			}
		}
		hashbuilder.Write(buffer[:read])
	}

	digest := hashbuilder.Sum(nil)
	if len(digest) != 32 {
		panic(errors.New("sha256 digest length should be 32"))
	}

	var buff [32]byte
	copy(buff[:], digest)
	return &buff, nil
}

/* Creates an UpdateArtifact.
	If URI is empty, the firmware image will be integrated into the artifact.
*/
func CreateArtifact(sequenceNumber uint64, hardwareUUID [16]byte, fwImagePath string, URI string, sigKeyPath string) (*UpdateArtifact, error) {
	if fwImagePath == "" {
		return nil, errors.New("must provide fwImagePath")
	}

	if sigKeyPath == "" {
		return nil, errors.New("must provide sigKeyPath")
	}

	var header UpdateHeader
	sequenceBuff := [8]byte{}
	binary.LittleEndian.PutUint64(sequenceBuff[:], sequenceNumber)

	ulBuff := [2]byte{}
	binary.LittleEndian.PutUint16(ulBuff[:], uint16(len(URI)))

	if URI == "" {
		header = UpdateHeader{SequenceNumber: sequenceBuff,
			HardwareUUID: hardwareUUID, URILength: ulBuff}
	} else {
		header = UpdateHeader{SequenceNumber: sequenceBuff,
			HardwareUUID: hardwareUUID, URILength: ulBuff, URIData: []byte(URI)}
	}

	image, err := os.Open(fwImagePath)
	defer image.Close()

	if err != nil {
		return nil, err
	}
	digest, err := header.CalcSHA256ArtifactDigest(image, 2041)
	if err != nil {
		return nil, err
	}

	artifact := UpdateArtifact{
		Header:      header,
		PayloadPath: fwImagePath,
	}

	err = artifact.AddRSASignature(*digest, sigKeyPath)

	return &artifact, err
}

func main() {
	fmt.Println("hallo")
	uriFlag := flag.String("uri", "", "Specify URI of FW-PayloadPath")
	outFlag := flag.String("out", "", "Specify output dir")
	keyFlag := flag.String("signKey", "", "Specify signature key")
	seqFlag := flag.String("seq", "", "Specify sequence number")
	imageFlag := flag.String("image", "", "Specify firmware image")
	uuidFlag := flag.String("uuid", "", "Specify uuid")

	flag.Parse()

	var art *UpdateArtifact
	var err error

	sequenceNum, err := strconv.ParseUint(*seqFlag, 10, 64)
	if err != nil {
		panic(err)
	}
	var uuidBuffer [16]byte
	copy(uuidBuffer[:], *uuidFlag)
	fmt.Println("imageflag", imageFlag)
	art, err = CreateArtifact(sequenceNum, uuidBuffer, *imageFlag, *uriFlag, *keyFlag)

	if err != nil {
		flag.PrintDefaults()
		panic(err)
	}
	fmt.Println(*outFlag)
	if *outFlag != "" {

		fmt.Println(art)
		blob, err := art.EncryptAndSerialize("", *outFlag)
		if err != nil {
			panic(err)
		}
		fmt.Println(blob)
	}
}
