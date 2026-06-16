package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

type PasswordEntry struct {
	ID       string `json:"id"`
	Service  string `json:"service"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type PasswordManager struct {
	masterKey []byte
	Entries   map[string]PasswordEntry
}

func NewPasswordManager(masterPassword string) (*PasswordManager, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	key := pbkdf2.Key([]byte(masterPassword), salt, 100000, 32, sha256.New)

	return &PasswordManager{
		masterKey: key,
		Entries:   make(map[string]PasswordEntry),
	}, nil
}

func (pm *PasswordManager) encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(pm.masterKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func (pm *PasswordManager) decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(pm.masterKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ct := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func (pm *PasswordManager) AddEntry(service, username, password string) (string, error) {
	encrypted, err := pm.encrypt([]byte(password))
	if err != nil {
		return "", err
	}

	id := fmt.Sprintf("%x", sha256.Sum256([]byte(service+username+string(encrypted))))

	entry := PasswordEntry{
		ID:       id,
		Service:  service,
		Username: username,
		Password: string(encrypted),
	}

	pm.Entries[id] = entry
	return id, nil
}

func (pm *PasswordManager) GetPassword(id string) (string, error) {
	entry, ok := pm.Entries[id]
	if !ok {
		return "", fmt.Errorf("entry not found")
	}

	decrypted, err := pm.decrypt([]byte(entry.Password))
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}

func (pm *PasswordManager) SaveToFile(filename string) error {
	data, err := json.Marshal(pm.Entries)
	if err != nil {
		return err
	}

	encrypted, err := pm.encrypt(data)
	if err != nil {
		return err
	}

	return os.WriteFile(filename, encrypted, 0600)
}

func LoadFromFile(masterPassword, filename string) (*PasswordManager, error) {
	encrypted, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	pm, err := NewPasswordManager(masterPassword)
	if err != nil {
		return nil, err
	}

	decrypted, err := pm.decrypt(encrypted)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(decrypted, &pm.Entries); err != nil {
		return nil, err
	}

	return pm, nil
}

func GeneratePassword(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
	b := make([]byte, length)
	for i := range b {
		num := make([]byte, 1)
		rand.Read(num)
		b[i] = charset[int(num[0])%len(charset)]
	}
	return string(b)
}

func main() {
	pm, err := NewPasswordManager("MySuperSecretPassword123!")
	if err != nil {
		fmt.Println("Ошибка создания менеджера:", err)
		return
	}

	id, err := pm.AddEntry("github.com", "myuser", "MyStrongPass2025!")
	if err != nil {
		fmt.Println("Ошибка добавления:", err)
		return
	}
	fmt.Println("✅ Добавлена запись с ID:", id)

	pass, err := pm.GetPassword(id)
	if err != nil {
		fmt.Println("Ошибка получения пароля:", err)
		return
	}
	fmt.Println("🔑 Полученный пароль:", pass)

	err = pm.SaveToFile("passwords.dat")
	if err != nil {
		fmt.Println("Ошибка сохранения:", err)
	} else {
		fmt.Println("💾 Данные сохранены в passwords.dat")
	}

	fmt.Println("🎲 Сгенерированный пароль:", GeneratePassword(16))
}
