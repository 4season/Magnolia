package decryptor

import "testing"

func TestDecryptSuccess(t *testing.T) {
	// 실제 데이터로 복호화 테스트
	result, err := Decrypt(7100372952644329473, 31, "q43eXIgA3c1UsjBcvG7a4LN9bXv4K3W5pV9aw62lUA8=")
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
	t.Logf("✅ 복호화 성공! 결과: %s", result)
}

func TestDecryptEmptyCiphertext(t *testing.T) {
	// 빈 암호문은 복호화에 실패해야 함
	_, err := Decrypt(12345, 0, "")
	if err == nil {
		t.Error("expected error for empty ciphertext, got nil")
	}
}
