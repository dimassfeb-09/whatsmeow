// Copyright (c) 2025 Dimas Febriyanto
//
// Desktop storage parity — DPAPI-equiv helper
//
// WhatsApp Desktop (MSIX 2.2634.101.0) persists device state under
//   %LocalAppData%\Packages\5319275A.WhatsAppDesktop_*\LocalState\
// encrypted at-rest via Windows DPAPI (CryptProtectData, user scope).
// Keys: NoiseKey, IdentityKey, SignedPreKey, AdvSecretKey etc.
//
// whatsmeow/sqlstore persists the same Device fields in plain SQLite
// (container.db / whatsmeow.db). In desktop parity mode we provide a
// portable DPAPI-equivalent so the fork can mimic Desktop's at-rest
// protection on Linux (where DPAPI doesn't exist) — AES-GCM with a
// machine-bound key derived from crypto/rand + stored 0600. This is
// NOT wire-compatible with DPAPI; it's a parity helper for operators
// who want Desktop-like encrypted-at-rest semantics on Linux VPS.
//
// References:
//   - Decompiled: WhatsAppNative.dll / WhatsAppNativeProjection.dll
//   - AppxManifest.xml Identity 5319275A.WhatsAppDesktop
//   - store/store.go Device (NoiseKey, IdentityKey, SignedPreKey)
//   - store/sqlstore/container.go Container
package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
)

// DesktopStorageKeyInfo documents where Desktop stores state vs whatsmeow.
// Desktop: %LocalAppData%\Packages\5319275A.WhatsAppDesktop_*\LocalState\
// whatsmeow: SQLite via sqlstore (whatsmeow.db + _foreign_keys=on)
const DesktopLocalStatePath = `%LocalAppData%\Packages\5319275A.WhatsAppDesktop_*\LocalState\`

// DesktopStorageKeyLen is the AES-256 key length used by the parity helper.
// DPAPI internally uses user-bound AES; we mimic with AES-256-GCM.
const DesktopStorageKeyLen = 32

// DeriveDesktopStorageKey derives a 32-byte key from a passphrase (e.g.
// machine-id + user secret) via SHA-256. Callers should store the raw key
// 0600 and never log it. This mirrors DPAPI's user-scope binding in a
// portable way.
func DeriveDesktopStorageKey(passphrase string) []byte {
	h := sha256.Sum256([]byte(passphrase))
	out := make([]byte, 32)
	copy(out, h[:])
	return out
}

// EncryptForDesktopStorage encrypts plaintext with AES-GCM using key (32 bytes).
// Returns hex(nonce|ciphertext). Mirrors DPAPI CryptProtectData at-rest intent.
func EncryptForDesktopStorage(key, plaintext []byte) (string, error) {
	if len(key) != DesktopStorageKeyLen {
		return "", fmt.Errorf("desktop storage key must be %d bytes, got %d", DesktopStorageKeyLen, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, plaintext, nil)
	return hex.EncodeToString(ct), nil
}

// DecryptForDesktopStorage decrypts hex(nonce|ciphertext) produced by EncryptForDesktopStorage.
func DecryptForDesktopStorage(key []byte, hexCiphertext string) ([]byte, error) {
	if len(key) != DesktopStorageKeyLen {
		return nil, fmt.Errorf("desktop storage key must be %d bytes, got %d", DesktopStorageKeyLen, len(key))
	}
	raw, err := hex.DecodeString(hexCiphertext)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(raw) < ns {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := raw[:ns], raw[ns:]
	return gcm.Open(nil, nonce, ct, nil)
}
