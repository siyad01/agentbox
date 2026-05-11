package vault

import (
	"os"
	"testing"
)

func TestStore_AddAndGet(t *testing.T) {
	tmpPath := "/tmp/agentbox-test-vault.json"
	defer os.Remove(tmpPath)
	defer os.Remove(tmpPath + ".tmp")

	store, err := NewStore(tmpPath, "test-password-123")
	if err != nil {
		t.Fatalf("cannot create store: %v", err)
	}

	// Add a credential
	err = store.Add("ANTHROPIC_API_KEY", "sk-ant-test-12345")
	if err != nil {
		t.Fatalf("cannot add credential: %v", err)
	}

	// Retrieve it
	val, err := store.Get("ANTHROPIC_API_KEY")
	if err != nil {
		t.Fatalf("cannot get credential: %v", err)
	}
	if val != "sk-ant-test-12345" {
		t.Errorf("expected sk-ant-test-12345, got %s", val)
	}
	t.Log("✅ Credential stored and retrieved correctly")
}

func TestStore_WrongPassword(t *testing.T) {
	tmpPath := "/tmp/agentbox-test-vault2.json"
	defer os.Remove(tmpPath)

	// Store with one password
	store1, _ := NewStore(tmpPath, "correct-password")
	store1.Add("SECRET", "my-secret-value")

	// Try to read with wrong password
	store2, _ := NewStore(tmpPath, "wrong-password")
	_, err := store2.Get("SECRET")
	if err == nil {
		t.Error("expected error with wrong password, got nil")
	}
	t.Logf("✅ Wrong password correctly rejected: %v", err)
}

func TestStore_List(t *testing.T) {
	tmpPath := "/tmp/agentbox-test-vault3.json"
	defer os.Remove(tmpPath)

	store, _ := NewStore(tmpPath, "test-pass")
	store.Add("KEY_ONE", "value1")
	store.Add("KEY_TWO", "value2")
	store.Add("KEY_THREE", "value3")

	names, err := store.List()
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(names) != 3 {
		t.Errorf("expected 3 credentials, got %d", len(names))
	}
	t.Logf("✅ Listed %d credentials: %v", len(names), names)
}

func TestStore_Delete(t *testing.T) {
	tmpPath := "/tmp/agentbox-test-vault4.json"
	defer os.Remove(tmpPath)

	store, _ := NewStore(tmpPath, "test-pass")
	store.Add("TEMP_KEY", "temp-value")
	store.Delete("TEMP_KEY")

	_, err := store.Get("TEMP_KEY")
	if err == nil {
		t.Error("expected error after delete, got nil")
	}
	t.Log("✅ Deleted credential correctly inaccessible")
}

func TestStore_Update(t *testing.T) {
	tmpPath := "/tmp/agentbox-test-vault5.json"
	defer os.Remove(tmpPath)

	store, _ := NewStore(tmpPath, "test-pass")
	store.Add("MY_KEY", "original-value")
	store.Add("MY_KEY", "updated-value") // same name = update

	val, _ := store.Get("MY_KEY")
	if val != "updated-value" {
		t.Errorf("expected updated-value, got %s", val)
	}

	// Make sure only one entry exists
	names, _ := store.List()
	if len(names) != 1 {
		t.Errorf("expected 1 credential after update, got %d", len(names))
	}
	t.Log("✅ Credential updated correctly, no duplicates")
}

func TestInjector_InjectForAgent(t *testing.T) {
	tmpPath := "/tmp/agentbox-test-vault6.json"
	defer os.Remove(tmpPath)

	store, _ := NewStore(tmpPath, "test-pass")
	store.Add("ANTHROPIC_API_KEY", "sk-ant-test")
	store.Add("GMAIL_TOKEN", "gmail-token-test")

	inj := NewInjector(store)
	env, err := inj.InjectForAgent([]string{
		"ANTHROPIC_API_KEY",
		"GMAIL_TOKEN",
	})
	if err != nil {
		t.Fatalf("injection failed: %v", err)
	}
	if env["ANTHROPIC_API_KEY"] != "sk-ant-test" {
		t.Errorf("wrong ANTHROPIC_API_KEY value")
	}
	if env["GMAIL_TOKEN"] != "gmail-token-test" {
		t.Errorf("wrong GMAIL_TOKEN value")
	}

	// Test ToSlice
	slice := env.ToSlice()
	if len(slice) != 2 {
		t.Errorf("expected 2 env vars, got %d", len(slice))
	}
	t.Logf("✅ Injected %d credentials as env vars", len(slice))
}

func TestInjector_MissingCredential(t *testing.T) {
	tmpPath := "/tmp/agentbox-test-vault7.json"
	defer os.Remove(tmpPath)

	store, _ := NewStore(tmpPath, "test-pass")
	// Don't add any credentials

	inj := NewInjector(store)
	_, err := inj.InjectForAgent([]string{"MISSING_KEY"})
	if err == nil {
		t.Error("expected error for missing credential, got nil")
	}
	t.Logf("✅ Missing credential correctly reported: %v", err)
}