package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

var P, _ = new(big.Int).SetString("3557", 10)
var g = big.NewInt(3)
var h = big.NewInt(5)

const secretsFile = "client_secrets.json"
const encryptionKey = "a_secure_random_key!" // 16/24/32 bytes for AES

type SecretData struct {
	PasswordVal int    `json:"passwordVal"`
	RVal        string `json:"rVal"`
}

var clientSecrets = make(map[string]SecretData)

// ------------------- Encryption Helpers -------------------

func encryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher([]byte(encryptionKey))
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)
	return ciphertext, nil
}

func decryptData(data []byte) ([]byte, error) {
	block, err := aes.NewCipher([]byte(encryptionKey))
	if err != nil {
		return nil, err
	}

	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(data, data)
	return data, nil
}

// ------------------- File Handling -------------------

func loadSecrets() {
	data, err := os.ReadFile(secretsFile)
	if err != nil {
		fmt.Println("No secrets file found, starting fresh.")
		return
	}
	decryptedData, err := decryptData(data)
	if err != nil {
		fmt.Println("Error decrypting secrets file:", err)
		return
	}
	err = json.Unmarshal(decryptedData, &clientSecrets)
	if err != nil {
		fmt.Println("Error parsing secrets file:", err)
	} else {
		fmt.Println("Secrets loaded from file.")
	}
}

func saveSecrets() {
	raw, err := json.MarshalIndent(clientSecrets, "", "  ")
	if err != nil {
		fmt.Println("Error marshaling secrets:", err)
		return
	}
	encryptedData, err := encryptData(raw)
	if err != nil {
		fmt.Println("Error encrypting secrets:", err)
		return
	}
	err = os.WriteFile(secretsFile, encryptedData, 0600)
	if err != nil {
		fmt.Println("Error writing secrets file:", err)
	}
}

// ------------------- ZKP Operations -------------------

func pow(base, exp *big.Int) *big.Int {
	return new(big.Int).Exp(base, exp, P)
}

func mul(a, b *big.Int) *big.Int {
	tmp := new(big.Int).Mul(a, b)
	return tmp.Mod(tmp, P)
}

func computeChallenge(C, A *big.Int) *big.Int {
	concat := C.Text(16) + A.Text(16)
	hash := sha256.Sum256([]byte(concat))
	e := new(big.Int).SetBytes(hash[:])
	pMinus1 := new(big.Int).Sub(P, big.NewInt(1))
	e.Mod(e, pMinus1)
	return e
}

func storeSecret(username string, passVal int, rVal *big.Int) {
	clientSecrets[username] = SecretData{
		PasswordVal: passVal,
		RVal:        rVal.Text(16),
	}
	saveSecrets()
}

func retrieveSecret(username string, password int) (*big.Int, *big.Int, bool) {
	sd, ok := clientSecrets[username]
	if !ok {
		return nil, nil, false
	}
	if sd.PasswordVal != password {
		return nil, nil, false // Password mismatch
	}
	pval := big.NewInt(int64(sd.PasswordVal))
	rval := new(big.Int)
	rval.SetString(sd.RVal, 16)
	return pval, rval, true
}

// ------------------- Client Operations -------------------

func signUp(username string, passwordInt int) {
	passVal := big.NewInt(int64(passwordInt))
	rVal, _ := rand.Int(rand.Reader, new(big.Int).Sub(P, big.NewInt(2)))
	rVal.Add(rVal, big.NewInt(1))

	comm1 := pow(g, passVal)
	comm2 := pow(h, rVal)
	commitment := mul(comm1, comm2)
	commitmentHex := commitment.Text(16)

	start := time.Now()
	req := map[string]interface{}{
		"operation":  "SIGN_UP",
		"username":   username,
		"commitment": commitmentHex,
	}
	sendRequest(req)
	elapsed := time.Since(start)
	fmt.Printf("[Client] SignUp round-trip took: %v\n", elapsed)

	storeSecret(username, passwordInt, rVal)
}

func login(username string, password int) {
	pval, rval, ok := retrieveSecret(username, password)
	if !ok {
		fmt.Println("Invalid username or password.")
		return
	}
	C1 := pow(g, pval)
	C2 := pow(h, rval)
	CVal := mul(C1, C2)

	alpha, _ := rand.Int(rand.Reader, new(big.Int).Sub(P, big.NewInt(2)))
	alpha.Add(alpha, big.NewInt(1))
	beta, _ := rand.Int(rand.Reader, new(big.Int).Sub(P, big.NewInt(2)))
	beta.Add(beta, big.NewInt(1))

	A1 := pow(g, alpha)
	A2 := pow(h, beta)
	AVal := mul(A1, A2)

	eVal := computeChallenge(CVal, AVal)

	s1 := new(big.Int).Mul(eVal, pval)
	s1.Add(s1, alpha)
	s1.Mod(s1, new(big.Int).Sub(P, big.NewInt(1)))

	s2 := new(big.Int).Mul(eVal, rval)
	s2.Add(s2, beta)
	s2.Mod(s2, new(big.Int).Sub(P, big.NewInt(1)))

	start := time.Now()
	req := map[string]interface{}{
		"operation": "LOGIN",
		"username":  username,
		"A":         AVal.Text(16),
		"s1":        s1.Text(16),
		"s2":        s2.Text(16),
	}
	sendRequest(req)
	elapsed := time.Since(start)
	fmt.Printf("[Client] Login round-trip took: %v\n", elapsed)
}

func sendRequest(data map[string]interface{}) {
	raw, _ := json.Marshal(data)
	conn, err := net.Dial("tcp", "127.0.0.1:9998")
	if err != nil {
		fmt.Println("Error connecting to server:", err)
		return
	}
	defer conn.Close()

	fmt.Fprintf(conn, "%s\n", string(raw))
	resp, _ := bufio.NewReader(conn).ReadString('\n')
	fmt.Println("Server response:", strings.TrimSpace(resp))
}

// ------------------- Main Function -------------------

func main() {
	loadSecrets()

	for {
		fmt.Println("\nSelect an operation:")
		fmt.Println("1 - Sign Up")
		fmt.Println("2 - Login")
		fmt.Println("3 - Exit")
		var choice int
		fmt.Scan(&choice)

		switch choice {
		case 1:
			fmt.Println("Enter username:")
			var username string
			fmt.Scan(&username)

			fmt.Println("Enter password (integer for demo):")
			var pw int
			fmt.Scan(&pw)

			signUp(username, pw)
		case 2:
			fmt.Println("Enter username:")
			var username string
			fmt.Scan(&username)

			fmt.Println("Enter password (integer for demo):")
			var pw int
			fmt.Scan(&pw)

			login(username, pw)
		case 3:
			fmt.Println("Exiting client...")
			return
		default:
			fmt.Println("Invalid choice.")
		}
	}
}
