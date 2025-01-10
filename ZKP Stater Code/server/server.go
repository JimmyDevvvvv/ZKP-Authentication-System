package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os"
	"runtime"
	"strings"
	"time"
)

// Demo Group Params (small prime for demonstration!)
var P, _ = new(big.Int).SetString("3557", 10)
var g = big.NewInt(3)
var h = big.NewInt(5)

type UserRecord struct {
	Username   string `json:"username"`
	Commitment string `json:"commitment"`
}

// We'll store an array of user records in a JSON file on the server side
var serverDataFile = "server_data.json"
var userRecords []UserRecord

// ------------------- JSON Storage -------------------
func loadUserRecords() {
	data, err := os.ReadFile(serverDataFile)
	if err != nil {
		fmt.Println("No existing server data found, starting fresh.")
		return
	}
	if err := json.Unmarshal(data, &userRecords); err != nil {
		fmt.Println("Error parsing server_data.json:", err)
	} else {
		fmt.Println("Server data loaded from", serverDataFile)
	}
}

func saveUserRecords() {
	raw, err := json.MarshalIndent(userRecords, "", "  ")
	if err != nil {
		fmt.Println("Error marshaling user records:", err)
		return
	}
	err = os.WriteFile(serverDataFile, raw, 0644)
	if err != nil {
		fmt.Println("Error writing server_data.json:", err)
	}
}

// ------------------- Helper Math -------------------
func pow(base, exp *big.Int) *big.Int {
	return new(big.Int).Exp(base, exp, P)
}
func mul(a, b *big.Int) *big.Int {
	tmp := new(big.Int).Mul(a, b)
	return tmp.Mod(tmp, P)
}

// computeChallenge = H(C || A)
func computeChallenge(C, A *big.Int) *big.Int {
	cHex := C.Text(16)
	aHex := A.Text(16)
	concat := cHex + aHex
	hash := sha256.Sum256([]byte(concat))
	e := new(big.Int).SetBytes(hash[:])
	pMinus1 := new(big.Int).Sub(P, big.NewInt(1))
	e.Mod(e, pMinus1)
	return e
}

// ------------------- Handle Connection -------------------
func handleConnection(conn net.Conn) {
	// 1) Record start time
	startTime := time.Now()

	// 2) Record memory usage at start
	var memStart runtime.MemStats
	runtime.ReadMemStats(&memStart)

	defer conn.Close()
	reader := bufio.NewReader(conn)

	line, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("Error reading:", err)
		return
	}
	line = strings.TrimSpace(line)

	var req map[string]interface{}
	if err := json.Unmarshal([]byte(line), &req); err != nil {
		conn.Write([]byte("Invalid JSON\n"))
		return
	}

	operation := req["operation"].(string)
	switch operation {
	case "SIGN_UP":
		username := req["username"].(string)
		commitmentHex := req["commitment"].(string)

		userRecords = append(userRecords, UserRecord{
			Username:   username,
			Commitment: commitmentHex,
		})
		saveUserRecords()

		fmt.Printf("[Server] Received SIGN_UP for '%s' with commitment '%s'\n",
			username, commitmentHex)
		conn.Write([]byte("Enrollment successful.\n"))

	case "LOGIN":
		username := req["username"].(string)
		AHex := req["A"].(string)
		s1Hex := req["s1"].(string)
		s2Hex := req["s2"].(string)

		fmt.Printf("[Server] Received LOGIN for user '%s'. A=%s, s1=%s, s2=%s\n",
			username, AHex, s1Hex, s2Hex)

		// find the user's record
		var record *UserRecord
		for i := range userRecords {
			if userRecords[i].Username == username {
				record = &userRecords[i]
				break
			}
		}
		if record == nil {
			conn.Write([]byte("User not found.\n"))
			return
		}

		CVal := new(big.Int)
		CVal.SetString(record.Commitment, 16)

		AVal := new(big.Int)
		AVal.SetString(AHex, 16)

		s1Val := new(big.Int)
		s1Val.SetString(s1Hex, 16)
		s2Val := new(big.Int)
		s2Val.SetString(s2Hex, 16)

		eVal := computeChallenge(CVal, AVal)

		// left = g^s1 * h^s2
		left1 := pow(g, s1Val)
		left2 := pow(h, s2Val)
		left := mul(left1, left2)

		// right = A * (C^e)
		Ce := pow(CVal, eVal)
		right := mul(AVal, Ce)

		if left.Cmp(right) == 0 {
			conn.Write([]byte("Login successful (ZKP verified).\n"))
		} else {
			conn.Write([]byte("Login failed.\n"))
		}

	default:
		conn.Write([]byte("Invalid operation.\n"))
	}

	// 3) Capture end time + memory
	endTime := time.Now()
	var memEnd runtime.MemStats
	runtime.ReadMemStats(&memEnd)

	elapsed := endTime.Sub(startTime)
	memUsedDiff := int64(memEnd.Alloc) - int64(memStart.Alloc)

	fmt.Printf("[Server Metrics] Request handled in %v, MemAlloc change = %d bytes\n",
		elapsed, memUsedDiff)
}

// ------------------- Start Server -------------------
func startServer() {
	loadUserRecords()

	ln, err := net.Listen("tcp", ":9998")
	if err != nil {
		fmt.Println("Error listening:", err)
		os.Exit(1)
	}
	defer ln.Close()

	fmt.Println("Server listening on port 9998...")
	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("Accept error:", err)
			continue
		}
		go handleConnection(conn)
	}
}

func main() {
	startServer()
}
