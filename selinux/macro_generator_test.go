package selinux

import (
	"strings"
	"testing"

	"github.com/cici0602/pml-to-selinux/models"
)

// TestMacroGenerator_GenerateRequireBlock tests require block generation
func TestMacroGenerator_GenerateRequireBlock(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName: "httpd",
		Version:    "1.0.0",
		Types: []models.TypeDeclaration{
			{TypeName: "httpd_t"},
			{TypeName: "httpd_exec_t"},
		},
		Rules: []models.AllowRule{
			{
				SourceType:  "httpd_t",
				TargetType:  "user_home_t", // External type - should be in require
				Class:       "file",
				Permissions: []string{"read", "open"},
			},
			{
				SourceType:  "httpd_t",
				TargetType:  "tmp_t", // External type
				Class:       "dir",
				Permissions: []string{"search"},
			},
		},
	}

	generator := NewMacroGenerator(policy)
	result := generator.GenerateRequireBlock()

	// Check require block structure
	if !strings.Contains(result, "require {") {
		t.Error("Missing require block opening")
	}
	if !strings.Contains(result, "}") {
		t.Error("Missing require block closing")
	}

	// Check that external types are included
	if !strings.Contains(result, "type user_home_t;") {
		t.Error("Missing external type user_home_t in require block")
	}
	if !strings.Contains(result, "type tmp_t;") {
		t.Error("Missing external type tmp_t in require block")
	}

	// Check that policy's own types are NOT in require block
	if strings.Contains(result, "type httpd_t;") {
		t.Error("Policy's own types should not be in require block")
	}
	if strings.Contains(result, "type httpd_exec_t;") {
		t.Error("Policy's own types should not be in require block")
	}

	// Check class permissions
	if !strings.Contains(result, "class file") {
		t.Error("Missing file class in require block")
	}
	if !strings.Contains(result, "class dir") {
		t.Error("Missing dir class in require block")
	}
}

// TestMacroGenerator_EmptyRequire tests minimal require block
func TestMacroGenerator_EmptyRequire(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName: "test",
		Version:    "1.0.0",
		Types: []models.TypeDeclaration{
			{TypeName: "test_t"},
		},
		Rules: []models.AllowRule{
			{
				SourceType:  "test_t",
				TargetType:  "test_t", // Only uses own types
				Class:       "file",
				Permissions: []string{"read"},
			},
		},
	}

	generator := NewMacroGenerator(policy)
	result := generator.GenerateRequireBlock()

	// Should still have class/permission requirements even without external types
	if !strings.Contains(result, "class file") {
		t.Error("Should include class file even without external types")
	}

	// But should not include the policy's own types
	if strings.Contains(result, "type test_t;") {
		t.Error("Should not include policy's own types in require block")
	}
}

// TestMacroGenerator_GenerateCommonMacros tests common macro generation
func TestMacroGenerator_GenerateCommonMacros(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName: "httpd",
		Version:    "1.0.0",
	}

	generator := NewMacroGenerator(policy)
	macros := generator.GenerateCommonMacros()

	// Should generate 4 standard macros
	expectedMacros := []string{
		"httpd_read",
		"httpd_write",
		"httpd_exec",
		"httpd_domtrans",
	}

	if len(macros) != len(expectedMacros) {
		t.Errorf("Expected %d macros, got %d", len(expectedMacros), len(macros))
	}

	// Check each macro
	foundMacros := make(map[string]bool)
	for _, macro := range macros {
		foundMacros[macro.Name] = true

		// Check that each macro has required fields
		if macro.Name == "" {
			t.Error("Macro has empty name")
		}
		if macro.Description == "" {
			t.Error("Macro has empty description")
		}
		if len(macro.Parameters) == 0 {
			t.Error("Macro has no parameters")
		}
		if macro.Body == "" {
			t.Error("Macro has empty body")
		}
	}

	for _, expected := range expectedMacros {
		if !foundMacros[expected] {
			t.Errorf("Missing expected macro: %s", expected)
		}
	}
}

// TestMacroGenerator_MacroContent tests macro body content
func TestMacroGenerator_MacroContent(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName: "httpd",
		Version:    "1.0.0",
	}

	generator := NewMacroGenerator(policy)
	macros := generator.GenerateCommonMacros()

	for _, macro := range macros {
		switch macro.Name {
		case "httpd_read":
			if !strings.Contains(macro.Body, "read_file_perms") {
				t.Error("httpd_read macro should contain read_file_perms")
			}
			if !strings.Contains(macro.Body, "list_dir_perms") {
				t.Error("httpd_read macro should contain list_dir_perms")
			}

		case "httpd_write":
			if !strings.Contains(macro.Body, "write_file_perms") {
				t.Error("httpd_write macro should contain write_file_perms")
			}
			if !strings.Contains(macro.Body, "rw_dir_perms") {
				t.Error("httpd_write macro should contain rw_dir_perms")
			}

		case "httpd_exec":
			if !strings.Contains(macro.Body, "can_exec") {
				t.Error("httpd_exec macro should contain can_exec")
			}
			if !strings.Contains(macro.Body, "httpd_exec_t") {
				t.Error("httpd_exec macro should reference httpd_exec_t")
			}

		case "httpd_domtrans":
			if !strings.Contains(macro.Body, "domtrans_pattern") {
				t.Error("httpd_domtrans macro should contain domtrans_pattern")
			}
			if !strings.Contains(macro.Body, "httpd_t") {
				t.Error("httpd_domtrans macro should reference httpd_t")
			}
		}
	}
}

// TestMacroGenerator_GenerateMacroFile tests complete macro file generation
func TestMacroGenerator_GenerateMacroFile(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName: "httpd",
		Version:    "1.0.0",
	}

	generator := NewMacroGenerator(policy)
	result := generator.GenerateMacroFile()

	// Check header
	if !strings.Contains(result, "# SELinux Macros for httpd") {
		t.Error("Missing macro file header")
	}

	// Check interface declarations
	expectedInterfaces := []string{
		"interface(`httpd_read',`",
		"interface(`httpd_write',`",
		"interface(`httpd_exec',`",
		"interface(`httpd_domtrans',`",
	}

	for _, iface := range expectedInterfaces {
		if !strings.Contains(result, iface) {
			t.Errorf("Missing interface declaration: %s", iface)
		}
	}

	// Check documentation format
	if !strings.Contains(result, "## <summary>") {
		t.Error("Missing summary documentation")
	}
	if !strings.Contains(result, "## <param name=") {
		t.Error("Missing parameter documentation")
	}
}

// TestMacroGenerator_CustomMacros tests custom macro inclusion
func TestMacroGenerator_CustomMacros(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName: "test",
		Version:    "1.0.0",
		Macros: []models.MacroDefinition{
			{
				Name:        "test_custom_macro",
				Description: "Custom macro for testing",
				Parameters:  []string{"domain", "file_type"},
				Body:        "allow $1 $2:file { read write };",
			},
		},
	}

	generator := NewMacroGenerator(policy)
	result := generator.GenerateMacroFile()

	// Check custom macro is included
	if !strings.Contains(result, "interface(`test_custom_macro',`") {
		t.Error("Missing custom macro interface")
	}
	if !strings.Contains(result, "Custom macro for testing") {
		t.Error("Missing custom macro description")
	}
	if !strings.Contains(result, "allow $1 $2:file { read write };") {
		t.Error("Missing custom macro body")
	}
}

// TestMacroGenerator_SortedTypes tests that types in require block are sorted
func TestMacroGenerator_SortedTypes(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName: "test",
		Version:    "1.0.0",
		Rules: []models.AllowRule{
			{
				SourceType:  "test_t",
				TargetType:  "ztype_t",
				Class:       "file",
				Permissions: []string{"read"},
			},
			{
				SourceType:  "test_t",
				TargetType:  "atype_t",
				Class:       "file",
				Permissions: []string{"read"},
			},
			{
				SourceType:  "test_t",
				TargetType:  "mtype_t",
				Class:       "file",
				Permissions: []string{"read"},
			},
		},
	}

	generator := NewMacroGenerator(policy)
	result := generator.GenerateRequireBlock()

	// Find positions (should be alphabetically sorted)
	atypeIdx := strings.Index(result, "type atype_t;")
	mtypeIdx := strings.Index(result, "type mtype_t;")
	ztypeIdx := strings.Index(result, "type ztype_t;")

	if atypeIdx == -1 || mtypeIdx == -1 || ztypeIdx == -1 {
		t.Fatal("Missing types in require block")
	}

	if !(atypeIdx < mtypeIdx && mtypeIdx < ztypeIdx) {
		t.Error("Types not sorted alphabetically in require block")
	}
}

// TestMacroGenerator_WithTransitions tests require block with transitions
func TestMacroGenerator_WithTransitions(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName: "test",
		Version:    "1.0.0",
		Types: []models.TypeDeclaration{
			{TypeName: "test_t"},
		},
		Transitions: []models.TypeTransition{
			{
				SourceType: "init_t", // External type
				TargetType: "test_exec_t",
				Class:      "process",
				NewType:    "test_t",
			},
		},
	}

	generator := NewMacroGenerator(policy)
	result := generator.GenerateRequireBlock()

	// Check that transition source is in require
	if !strings.Contains(result, "type init_t;") {
		t.Error("Missing init_t from transition in require block")
	}

	// Check that class is included
	if !strings.Contains(result, "class process") {
		t.Error("Missing process class from transition in require block")
	}
}

// TestGenerateRequireStatements tests the convenience function
func TestGenerateRequireStatements(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName: "test",
		Version:    "1.0.0",
		Rules: []models.AllowRule{
			{
				SourceType:  "test_t",
				TargetType:  "external_t",
				Class:       "file",
				Permissions: []string{"read"},
			},
		},
	}

	result := GenerateRequireStatements(policy)

	if !strings.Contains(result, "require {") {
		t.Error("GenerateRequireStatements should generate require block")
	}
	if !strings.Contains(result, "type external_t;") {
		t.Error("GenerateRequireStatements should include external types")
	}
}

// TestGenerateMacros tests the convenience function
func TestGenerateMacros(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName: "test",
		Version:    "1.0.0",
	}

	result := GenerateMacros(policy)

	if !strings.Contains(result, "# SELinux Macros for test") {
		t.Error("GenerateMacros should generate macro file header")
	}
	if !strings.Contains(result, "interface(`test_read',`") {
		t.Error("GenerateMacros should generate standard macros")
	}
}
