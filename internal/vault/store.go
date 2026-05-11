package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

type StoredCredential struct {
	Name string `json:"name"`
	Encrypted []byte `json:"encrypted"`
	Nonce []byte `json:"nonce"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type VaultFile struct {
	Version string `json:"version"`
	Credentials []StoredCredential `json:"credentials"`
}

type Store struct {
	path string
	key []byte
}

func NewStore(path, masterPassword string) (*Store, error) {

	hash := sha256.Sum256([]byte(masterPassword))

	s := &Store{
		path: path,
		key: hash[:],
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		empty := VaultFile{Version: "1.0"}
		if err := s.save(empty); err != nil {
			return nil, fmt.Errorf("cannot create vault: %w", err)
		}
	}

	return s, nil
}

func (s *Store) Add(name, value string) error {
	vault, err := s.load()
	if err != nil {
		return err
	}

	encrypted, nonce, err := s.encrypt([]byte(value))

	if err != nil {
		return fmt.Errorf("cannot encrypt credential: %w", err)
	}

	now := time.Now().UTC().Format(time.RFC3339)

	found := false
	for i, c := range vault.Credentials {
		if c.Name == name {
			vault.Credentials[i].Encrypted = encrypted
			vault.Credentials[i].Nonce = nonce
			vault.Credentials[i].UpdatedAt = now	
			found = true
			break
		}
	}
	if !found {
		vault.Credentials = append(vault.Credentials, StoredCredential{
			Name: name,
			Encrypted: encrypted,
			Nonce: nonce,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return s.save(vault)
}

func (s *Store) Get(name string) (string, error) {
	vault, err := s.load()
	if err != nil {
		return "", err
	}

	for _, c := range vault.Credentials {
		if c.Name == name {
			plain, err := s.decrypt(c.Encrypted, c.Nonce)
			if err != nil {
				return "", fmt.Errorf("cannot decrypt %q: %w", name, err)
			}
			return string(plain), nil
		}
	}
	return "", fmt.Errorf("credential %q not found in vault", name)
}

func (s *Store) Delete(name string) error {
	vault, err := s.load()
	if err != nil {
		return err
	}

	newCreds := []StoredCredential{}
	found := false
	for _, c := range vault.Credentials {
		if c.Name == name {
			found = true
			continue
		}
		newCreds = append(newCreds, c)
	}

	if !found {
		return fmt.Errorf("credential %q not found", name)
	}

	vault.Credentials = newCreds
	return s.save(vault)
}


func (s *Store) List() ([]string, error) {
	vault, err := s.load()
	if err != nil {
		return nil, err
	}

	names := make([]string, len(vault.Credentials))
	for i, c := range vault.Credentials {
		names[i] = c.Name
	}
	return names, nil
}

func (s *Store) encrypt(plaintext []byte) (ciphertext, nonce []byte, err error) {

	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

func (s *Store) decrypt(ciphertext, nonce []byte) ([]byte, error) {

	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("decryption failed: wrong password or tampered vault")
	}
	return plaintext, nil
}


func (s *Store) load() (VaultFile, error) {

	data, err := os.ReadFile(s.path)

	if err != nil {
		return VaultFile{}, fmt.Errorf("cannot read vault: %w", err)
	}

	var vault VaultFile
	if err := json.Unmarshal(data, &vault); err != nil {
		return VaultFile{}, fmt.Errorf("cannot parse vault: %w", err)
	}

	return vault, nil
}

func (s *Store) save(vault VaultFile) error {
	data, err := json.MarshalIndent(vault, "", " ")
	if err != nil {
		return fmt.Errorf("cannot serialize vault: %w", err)
	}

	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("cannot write vault: %w", err)
	}
	return os.Rename(tmp, s.path)
}