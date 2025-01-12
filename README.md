# Zero-Knowledge Proof (ZKP) Authentication System

## Project Overview
This project implements a one-factor authentication system using Zero-Knowledge Proofs (ZKPs) in Go. The system ensures secure authentication by allowing users to prove their identity without transmitting passwords over the network. The architecture employs a client-server model, with ZKP-based commitment and verification protocols.

---

## Features

### 1. Core Functionalities
- **Enrollment / Sign-Up:**
  - Clients generate a cryptographic commitment using their password and a random value (r).
  - Commitments are securely stored on the server.
- **Authentication / Sign-In:**
  - Clients generate ZKP-based proofs using stored commitments and send them to the server.
  - The server verifies the proofs against commitments to authenticate users.

### 2. Security Features
- **Zero-Knowledge Proofs:**
  - Ensures passwords are never directly transmitted over the network.
  - Enhances user privacy while maintaining robust security.
- **Data Encryption:**
  - Client secrets are stored locally in encrypted form for additional security.

### 3. Performance Metrics
- **Efficiency Metrics:**
  - CPU and memory usage on both client and server during authentication.
  - Time taken for proof generation, transmission, and verification.

---

## Technology Stack
- **Programming Language:** Go
- **Cryptographic Operations:** SHA-256, Modular Arithmetic
- **Data Storage:**
  - Server-side: JSON file (`server_data.json`) for commitments.
  - Client-side: Encrypted secrets file (`client_secrets.json`).
- **Communication Protocol:** TCP socket programming

---

## Setup Instructions

### Prerequisites
- Install Go (version 1.18 or higher).

### Steps
1. **Clone the Repository:**
   ```bash
   git clone [repository URL]
   ```
2. **Navigate to the Project Directory:**
   ```bash
   cd ZKP_Authentication
   ```
3. **Run the Server:**
   ```bash
   go run server.go
   ```
4. **Run the Client:**
   ```bash
   go run client.go
   ```

---

## Usage Instructions

### Enrollment (Sign-Up):
1. Launch the client and choose the **Sign-Up** option.
2. Enter a username and password.
3. The client computes a commitment and sends it to the server for storage.

### Authentication (Sign-In):
1. Launch the client and choose the **Sign-In** option.
2. Enter your username and password.
3. The client computes a ZKP proof and sends it to the server.
4. The server verifies the proof and returns the authentication result.

---

## Key Components

### Server (`server.go`):
- Handles user enrollment and authentication requests.
- Verifies ZKP proofs and ensures secure communication.
- Stores commitments in a JSON file (`server_data.json`).

### Client (`client.go`):
- Generates commitments and ZKP proofs using user inputs.
- Encrypts and stores local secrets in `client_secrets.json`.
- Communicates with the server over a TCP connection.

---

## Performance Metrics
1. **Efficiency Metrics:**
   - Monitor CPU and memory usage during client-server operations.
   - Measure round-trip time for proof generation and verification.
2. **Usability Metrics:**
   - Evaluate ease of use for enrollment and authentication.

---

## Deliverables
- **Source Code:**
  - `server.go` - Server-side logic for ZKP authentication.
  - `client.go` - Client-side logic for proof generation and communication.
- **Sample Data:**
  - `server_data.json` - Stores user commitments.
  - `client_secrets.json` - Encrypted client-side secrets.




