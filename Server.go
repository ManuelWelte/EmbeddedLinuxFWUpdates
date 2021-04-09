package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type PendingUpdate struct {
	UpdateId  uint32 `json:"updateId"`
	Timestamp int64  `json:"timestamp"`
}

type PrepareUpdateData struct {
	Keys      []DecryptionKeyCiphertext `json:"keys"`
	Available int64                     `json:"available"`
}

var pendingUpdates = make(map[string][]PendingUpdate)

func reserveID() (uint32, error) {
	storageDir := "artifacts"
	var fileNames []uint32

	filepath.Walk(storageDir, func(path string, info os.FileInfo, err error) error {
		fmt.Println(path)
		// don't check recursively
		if strings.Count(path, "/") > 1 {
			return nil
		}
		// if it's an update directory, the conversion will succeed;
		// otherwise, just ignore the error
		num, err := strconv.ParseUint(info.Name(), 10, 32)
		if err == nil {
			fileNames = append(fileNames, uint32(num))
		}
		return nil
	})

	sort.Slice(fileNames, func(i, j int) bool { return fileNames[i] < fileNames[j] })
	fmt.Println(fileNames)
	newId := uint32(0)
	for i := uint32(0); i < uint32(len(fileNames)); i++ {
		if fileNames[i] != i {
			break
		}
		newId++
	}
	return newId, nil
}

type DecryptionKeyIVPair struct {
	CT [256]byte `json:"ct"`
	IV [12]byte  `json:"iv"`
}

type DecryptionKeyCiphertext struct {
	SAN string    `json:"san"`
	CT  [256]byte `json:"ct"`
	IV  [12]byte  `json:"iv"`
}

func getDecryptionKey(w http.ResponseWriter, req *http.Request) {
	params, ok := req.URL.Query()["updateId"]

	if !ok || len(params[0]) < 1 {
		w.WriteHeader(400)
		return
	}

	sUpdateId, err := strconv.Atoi(params[0])
	if err != nil {
		w.WriteHeader(400)
		return
	}

	updateId := uint32(sUpdateId)

	if len(req.TLS.PeerCertificates[0].DNSNames) < 1 {
		w.WriteHeader(403)
		return
	}

	deviceName := req.TLS.PeerCertificates[0].DNSNames[0]

	keyPath := fmt.Sprintf("artifacts/%d/%s", updateId, deviceName)

	key, err := ioutil.ReadFile(keyPath)
	if err != nil {
		if os.IsNotExist(err) {
			w.WriteHeader(404)
		} else {
			w.WriteHeader(503)
		}
		return
	}
	ivPath := fmt.Sprintf("artifacts/%d/%s_iv", updateId, deviceName)

	iv, err := ioutil.ReadFile(ivPath)

	if err != nil {
		if os.IsNotExist(err) {
			w.WriteHeader(404)
		} else {
			w.WriteHeader(503)
		}
		return
	}

	var decryptionIVpair DecryptionKeyIVPair
	copy(decryptionIVpair.IV[:], iv)
	copy(decryptionIVpair.CT[:], key)

	jsonB, err := json.Marshal(decryptionIVpair)
	if err != nil {
		w.WriteHeader(503)
		return
	}

	w.WriteHeader(200)
	w.Write(jsonB)
}

func PrepareUpdate(w http.ResponseWriter, req *http.Request) {

	fmt.Println("Preparing Update")
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		w.WriteHeader(400)
		fmt.Println(err)
		return
	}

	var dat PrepareUpdateData
	err = json.Unmarshal(body, &dat)
	if err != nil {
		w.WriteHeader(400)
		fmt.Println(err)
		return
	}

	newId, err := PrepareUpdateDirectory(dat.Keys, 0)

	if err != nil {
		w.WriteHeader(503)
		fmt.Println(err)
		return
	}

	fmt.Fprint(w, newId)
}

// Creates directory for artifact and ciphertexts and stores ciphertexts in it
// auto-deletion date not yet supported
func PrepareUpdateDirectory(keyList []DecryptionKeyCiphertext, available int64) (uint32, error) {

	newId, err := reserveID()

	fmt.Printf("NewId = %d\n", newId)

	if err != nil {
		return 0, err
	}

	artifactPath := fmt.Sprintf("artifacts/%d", newId)

	// TODO: Find appropriate permission
	err = os.Mkdir(artifactPath, 0755)

	if err != nil {
		return 0, err
	}

	for _, ciphertext := range keyList {
		ciphertextPath := fmt.Sprintf("%s/%s", artifactPath, ciphertext.SAN)
		ivPath := fmt.Sprintf("%s_iv", ciphertextPath)
		err = ioutil.WriteFile(ciphertextPath, ciphertext.CT[:], 0777)
		err = ioutil.WriteFile(ivPath, ciphertext.IV[:], 0777)
		if err != nil {
			return 0, err
		}
	}

	timestampPath := fmt.Sprintf("%s/timestamp_%d", artifactPath, newId)
	fmt.Println("Timestamp-Path= ", timestampPath)

	timeBuff := make([]byte, 8)
	binary.LittleEndian.PutUint64(timeBuff, uint64(available))
	err = ioutil.WriteFile(timestampPath, timeBuff, 777)

	return newId, nil
}

func whatsNew(w http.ResponseWriter, req *http.Request) {

	if len(req.TLS.PeerCertificates[0].DNSNames) < 1 {
		w.WriteHeader(403)
		return
	}

	deviceName := req.TLS.PeerCertificates[0].DNSNames[0]
	updates := pendingUpdates[deviceName]

	if updates == nil {
		w.WriteHeader(204)
		return
	}

	avUpdates := make([]uint32, 0)
	for _, upd := range updates {
		if time.Now().Unix() > upd.Timestamp {
			avUpdates = append(avUpdates, upd.UpdateId)
		}
	}

	if len(avUpdates) == 0 {
		w.WriteHeader(204)
		return
	}

	jsonB, err := json.Marshal(avUpdates)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(500)
	} else {
		w.Write(jsonB)
	}
}

func uploadArtifact(w http.ResponseWriter, req *http.Request) {
	params, ok := req.URL.Query()["updateId"]

	if !ok || len(params[0]) < 1 {
		log.Println("No UpdateId parameter")
		w.WriteHeader(403)
		return
	}
	sUpdateId, err := strconv.Atoi(params[0])
	updateId := uint32(sUpdateId)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(400)
		return
	}

	updatePath := fmt.Sprintf("artifacts/%d", updateId)
	if _, err := os.Stat(updatePath); err != nil {
		fmt.Println(err)
		// No dir has been prepared for that ID
		w.WriteHeader(400)
		return
	}

	artifactPath := fmt.Sprintf("%s/%d", updatePath, updateId)
	if _, err := os.Stat(artifactPath); err == nil {
		// Artifact already exists
		fmt.Fprint(w, "File already exists")
		w.WriteHeader(400)
		return
	}

	body, err := ioutil.ReadAll(req.Body)
	if body == nil {
		return
	}
	err = ioutil.WriteFile(artifactPath, body, 0777)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(503)
		return
	}
	fmt.Println("Wrote file to ", artifactPath)
	err = setup()
	if err != nil {
		panic(err)
	}
}

func getUpdate(w http.ResponseWriter, req *http.Request) {
	params, ok := req.URL.Query()["updateId"]

	if !ok || len(params[0]) < 1 {
		w.WriteHeader(400)
		return
	}

	sUpdateId, err := strconv.Atoi(params[0])
	if err != nil {
		w.WriteHeader(400)
		return
	}

	updateId := uint32(sUpdateId)

	if len(req.TLS.PeerCertificates[0].DNSNames) < 1 {
		w.WriteHeader(403)
		return
	}

	deviceName := req.TLS.PeerCertificates[0].DNSNames[0]

	privileged := false

	for _, update := range pendingUpdates[deviceName] {
		if update.UpdateId == updateId {
			privileged = true
		}
	}

	if !privileged {
		w.WriteHeader(401)
		return
	}

	artifactPath := fmt.Sprintf("artifacts/%d/%d", updateId, updateId)

	artifact, err := ioutil.ReadFile(artifactPath)
	if err != nil {
		if os.IsNotExist(err) {
			w.WriteHeader(404)
		} else {
			w.WriteHeader(503)
		}
		return
	}

	w.WriteHeader(200)
	_, err = w.Write(artifact)
	if err != nil {
		fmt.Println(err)
	}
}

func CreateHTTPSServer(rootCaCert string) (*http.Server, error) {

	http.HandleFunc("/getUpdate", getUpdate)
	http.HandleFunc("/getDecryptionKey", getDecryptionKey)
	http.HandleFunc("/uploadArtifact", uploadArtifact)
	http.HandleFunc("/whatsNew", whatsNew)
	http.HandleFunc("/prepareUpdate", PrepareUpdate)

	caCert, err := ioutil.ReadFile(rootCaCert)
	if err != nil {
		log.Fatal(err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}

	server := &http.Server{
		Addr:      ":8090",
		TLSConfig: tlsConfig,
	}

	return server, nil
}

func setup() error {

	fmt.Println("Doing setup")
	storageDir := "artifacts"
	if _, check := os.Stat(storageDir); os.IsNotExist(check) {
		err := os.Mkdir(storageDir,0777)
		if err!= nil {
			return err
		}
	}

	pendingUpdates = make(map[string][]PendingUpdate)
	err := filepath.Walk(storageDir, func(path string, info os.FileInfo, err error) error {

		if strings.Count(path, "/") == 2 {

			pathSlice := strings.SplitAfter(path, "/")
			artifactPath := fmt.Sprintf("%s%s%s", pathSlice[0], pathSlice[1], pathSlice[1][:len(pathSlice[1])-1])

			// Update artifact hasn't been uploaded yet, don't count as pending
			if _, check := os.Stat(artifactPath); os.IsNotExist(check) {
				return err
			}

			if path == artifactPath {
				return err
			}

			updateId64, err := strconv.ParseUint(strings.Replace(pathSlice[1], "/", "", 1), 10, 32)
			if err != nil {
				return err
			}

			updateId := uint32(updateId64)

			ivPath := fmt.Sprintf("%s%s_iv", pathSlice[0], pathSlice[1])
			if path == ivPath {
				return nil
			}

			timeStampPath := fmt.Sprintf("%s%stimestamp_%d", pathSlice[0], pathSlice[1], updateId)
			if path == timeStampPath {
				return nil
			}

			rawTimestamp, err := ioutil.ReadFile(timeStampPath)
			if err != nil {
				return err
			}

			timestamp := int64(binary.LittleEndian.Uint64(rawTimestamp))
			update := PendingUpdate{UpdateId: updateId, Timestamp: timestamp}

			pendingUpdates[info.Name()] = append(pendingUpdates[info.Name()], update)
			for _, updates := range pendingUpdates {
				sort.Slice(updates, func(i int, j int) bool { return updates[i].Timestamp > updates[j].Timestamp })
			}
		}

		return err
	})

	return err
}

func main() {

	err := setup()
	if err != nil {
		panic(err)
	}

	server, err := CreateHTTPSServer("ca-crt.pem")
	if err != nil {
		panic(err)
	}
	panic(server.ListenAndServeTLS("server.crt", "server.key"))
}
