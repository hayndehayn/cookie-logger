package main

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows DPAPI decryption wrapper
// Uses the built-in Windows Data Protection API

var (
	dllCrypt32             = syscall.NewLazyDLL("crypt32.dll")
	procCryptUnprotectData = dllCrypt32.NewProc("CryptUnprotectData")
)

type DataBlob struct {
	cbData uint32
	pbData *byte
}

// DPAPIDecrypt decrypts data encrypted with DPAPI
func DPAPIDecrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, syscall.EINVAL
	}

	cipherBlob := DataBlob{
		cbData: uint32(len(ciphertext)),
		pbData: &ciphertext[0],
	}

	var plainBlob DataBlob

	ret, _, err := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&cipherBlob)),
		0,
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&plainBlob)),
	)

	if ret == 0 {
		return nil, err
	}

	// Copy decrypted data
	plaintext := make([]byte, plainBlob.cbData)
	copy(plaintext, (*[1 << 30]byte)(unsafe.Pointer(plainBlob.pbData))[:plainBlob.cbData:plainBlob.cbData])

	// Free memory
	windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(plainBlob.pbData))))

	return plaintext, nil
}
