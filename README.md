# Password Manager in Go

This repository contains a simple, secure password manager written in Go. It allows users to safely store, retrieve, encrypt, and generate strong passwords.

---

## 🛠️ How It Works

The core logic is implemented in `project.go` using standard and external cryptographic libraries:

* **Key Derivation:** Uses **PBKDF2** with **SHA-256** and **100,000 iterations** to derive a secure cryptographic key from your master password.


* **Encryption:** Uses authenticated encryption via **AES-GCM** to securely encrypt both individual entry passwords and the entire database file (`passwords.dat`).


* **Storage:** Data is serialized to JSON, fully encrypted, and written locally with safe Unix file permissions (`0600`).



---

## 🚀 Getting Started

### Prerequisites

* **Go** version `1.26.4` or higher.



### Dependencies

This project utilizes the extended Go crypto libraries:

* `golang.org/x/crypto v0.53.0` (for PBKDF2 implementation).



---

## 💻 Usage

To initialize dependencies, run:

```bash
go mod tidy

```

To run the password manager application:

```bash
go run project.go

```

As demonstrated in the workspace snapshot **"Снимок экрана (1066).png"**, running the file automatically triggers password creation, encryption, secure local persistence, and test output verifying successful decryption.

---

## 🔒 Security Architecture Details

```
 [Master Password] + [Random Salt] 
               │
               ▼ (PBKDF2-SHA256, 100k rounds)
         [Master Key]
               │
               ├─► Encrypts Single Entry Passwords (AES-GCM)
               └─► Encrypts Full Export Database File (AES-GCM)

```

The application exposes the following key programmatic methods for managing credentials:

* `NewPasswordManager(masterPassword)`: Generates a new instance initialized with a unique derived salt and master key.


* `AddEntry(service, username, password)`: Encrypts a password and maps it against a uniquely computed SHA-256 transaction ID.


* `SaveToFile(filename)`: Encrypts the entire collection map and flushes it securely to disk.


* `GeneratePassword(length)`: Dynamically builds cryptographically secure, unpredictable password strings.
