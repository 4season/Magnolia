package decryptor

import "testing"

func TestDecryptInvalidI9(t *testing.T) {
	// i9 범위는 0~31이므로, 99는 유효하지 않음
	_, err := Decrypt(12345, 99, "dGVzdA==")
	if err == nil {
		t.Error("expected error for invalid i9, got nil")
	}
}

func TestDecryptEmptyCiphertext(t *testing.T) {
	// 빈 암호문은 복호화에 실패해야 함
	_, err := Decrypt(12345, 0, "")
	if err == nil {
		t.Error("expected error for empty ciphertext, got nil")
	}
}
