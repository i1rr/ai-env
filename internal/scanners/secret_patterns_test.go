package scanners

import (
	"testing"
)

// TestBuiltInSecretPatterns_MirrorsInternalSet verifies the
// exported view matches the internal patternRule set 1:1. The plan
// pins the parity requirement: callers that import this list rely
// on every internal pattern being represented.
func TestBuiltInSecretPatterns_MirrorsInternalSet(t *testing.T) {
	exported := BuiltInSecretPatterns()
	internal := builtinPatterns()
	if len(exported) != len(internal) {
		t.Fatalf("BuiltInSecretPatterns returned %d entries, internal builtinPatterns has %d", len(exported), len(internal))
	}
	for i, ext := range exported {
		if ext.Pattern == nil {
			t.Errorf("entry %d has nil Pattern", i)
			continue
		}
		if ext.Pattern.String() != internal[i].re.String() {
			t.Errorf("entry %d regex = %q, internal = %q", i, ext.Pattern.String(), internal[i].re.String())
		}
		if ext.Name != internal[i].name {
			t.Errorf("entry %d name = %q, internal = %q", i, ext.Name, internal[i].name)
		}
		if ext.Kind != internal[i].kind {
			t.Errorf("entry %d kind = %q, internal = %q", i, ext.Kind, internal[i].kind)
		}
	}
}

// TestBuiltInSecretPatterns_DetectsAnthropicKey is a smoke test that
// the exported view actually catches one of the canonical formats.
func TestBuiltInSecretPatterns_DetectsAnthropicKey(t *testing.T) {
	exported := BuiltInSecretPatterns()
	sample := "sk-ant-AABBCCDDEEFFGGHHIIJJKKLLMM"
	hit := false
	for _, p := range exported {
		if p.Pattern.MatchString(sample) {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("BuiltInSecretPatterns missed a canonical Anthropic key")
	}
}
