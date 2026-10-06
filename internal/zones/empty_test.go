package zones

import "testing"

func TestEmptyConfigRemovesTable(t *testing.T) {
	script, err := Generate(Config{})
	if err != nil || script != RemoveScript {
		t.Fatalf("empty config must yield the remove script, got %q, %v", script, err)
	}
}
