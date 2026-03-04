package decryptor

/*
#cgo LDFLAGS: -L${SRCDIR}/../../decryptor/target/release -ldecryptor
#include <stdlib.h>

// Rust FFI 함수 선언
extern char* decrypt_data_ffi(unsigned long long user_id, unsigned long i9, const char* ciphertext_b64);
extern void free_string(char* ptr);
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// Decrypt는 Rust decryptor를 호출하여 암호문을 복호화합니다.
// userID: 사용자 ID, i9: 타입 번호 (0~31), ciphertextB64: Base64 인코딩된 암호문
func Decrypt(userID uint64, i9 uint, ciphertextB64 string) (string, error) {
	// Go 문자열을 C 문자열로 변환 (Go가 메모리 할당)
	cCiphertext := C.CString(ciphertextB64)
	defer C.free(unsafe.Pointer(cCiphertext)) // Go가 할당한 메모리는 C.free로 해제

	// Rust FFI 함수 호출
	result := C.decrypt_data_ffi(
		C.ulonglong(userID),
		C.ulong(i9),
		cCiphertext,
	)

	// null 반환 = 복호화 실패
	if result == nil {
		return "", fmt.Errorf("decryption failed: user_id=%d, i9=%d", userID, i9)
	}
	// Rust가 할당한 메모리는 Rust의 free_string으로 해제
	defer C.free_string(result)

	// Go 힙으로 안전하게 복사 (free_string 호출 전에 복사 완료)
	return C.GoString(result), nil
}
