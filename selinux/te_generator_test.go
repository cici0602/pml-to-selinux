package selinux

import (
	"strings"
	"testing"

	"github.com/cici0602/pml-to-selinux/models"
)

// TestTEGenerator_Generate tests complete TE file generation
func TestTEGenerator_Generate(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName: "httpd",
		Version:    "1.0.0",
		Types: []models.TypeDeclaration{
			{
				TypeName:   "httpd_t",
				Attributes: []string{"domain"},
			},
			{
				TypeName:   "httpd_exec_t",
				Attributes: []string{"file_type", "exec_type"},
			},
		},
		Rules: []models.AllowRule{
			{
				SourceType:  "httpd_t",
				TargetType:  "httpd_exec_t",
				Class:       "file",
				Permissions: []string{"read", "execute", "open"},
			},
		},
	}

	generator := NewTEGenerator(policy)
	result, err := generator.Generate()

	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Check header
	if !strings.Contains(result, "# SELinux Policy Module: httpd") {
		t.Error("Missing module name in header")
	}
	if !strings.Contains(result, "# Version: 1.0.0") {
		t.Error("Missing version in header")
	}

	// Check policy_module declaration
	if !strings.Contains(result, "policy_module(httpd, 1.0.0)") {
		t.Error("Missing policy_module declaration")
	}

	// Check type declarations
	if !strings.Contains(result, "type httpd_t, domain;") {
		t.Error("Missing httpd_t type declaration")
	}
	if !strings.Contains(result, "type httpd_exec_t, file_type, exec_type;") {
		t.Error("Missing httpd_exec_t type declaration")
	}

	// Check allow rules
	if !strings.Contains(result, "allow httpd_t httpd_exec_t:file") {
		t.Error("Missing allow rule for httpd_t")
	}
	if !strings.Contains(result, "{ execute open read }") && !strings.Contains(result, "{ read execute open }") {
		t.Error("Missing or incorrect permissions in allow rule")
	}
}

// TestTEGenerator_EmptyPolicy tests generation with minimal policy
func TestTEGenerator_EmptyPolicy(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName: "empty",
		Version:    "1.0.0",
	}

	generator := NewTEGenerator(policy)
	result, err := generator.Generate()

	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Should have header and policy_module, but no types or rules
	if !strings.Contains(result, "policy_module(empty, 1.0.0)") {
		t.Error("Missing policy_module declaration")
	}

	// Should not have type declarations or allow rules sections
	if strings.Contains(result, "# Type Declarations") {
		t.Error("Should not have Type Declarations section for empty policy")
	}
	if strings.Contains(result, "# Allow Rules") {
		t.Error("Should not have Allow Rules section for empty policy")
	}
}

// TestTEGenerator_BooleanDeclarations tests boolean generation
func TestTEGenerator_BooleanDeclarations(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName: "test",
		Version:    "1.0.0",
		Booleans: []models.BooleanDeclaration{
			{
				Name:         "httpd_enable_homedirs",
				DefaultValue: false,
				Description:  "Allow httpd to read user home directories",
			},
			{
				Name:         "httpd_can_network_connect",
				DefaultValue: true,
				Description:  "Allow httpd to make network connections",
			},
		},
	}

	generator := NewTEGenerator(policy)
	result, err := generator.Generate()

	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Check boolean section header
	if !strings.Contains(result, "# Boolean Declarations") {
		t.Error("Missing Boolean Declarations section")
	}

	// Check first boolean
	if !strings.Contains(result, "gen_tunable(httpd_enable_homedirs, false)") {
		t.Error("Missing or incorrect httpd_enable_homedirs boolean")
	}
	if !strings.Contains(result, "Allow httpd to read user home directories") {
		t.Error("Missing description for httpd_enable_homedirs")
	}

	// Check second boolean
	if !strings.Contains(result, "gen_tunable(httpd_can_network_connect, true)") {
		t.Error("Missing or incorrect httpd_can_network_connect boolean")
	}
	if !strings.Contains(result, "Allow httpd to make network connections") {
		t.Error("Missing description for httpd_can_network_connect")
	}
}

// TestTEGenerator_TypeDeclarations tests type declaration generation
func TestTEGenerator_TypeDeclarations(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName: "test",
		Version:    "1.0.0",
		Types: []models.TypeDeclaration{
			{
				TypeName: "simple_t",
			},
			{
				TypeName:   "domain_t",
				Attributes: []string{"domain"},
			},
			{
				TypeName:   "file_t",
				Attributes: []string{"file_type", "data_file_type"},
			},
		},
	}

	generator := NewTEGenerator(policy)
	result, err := generator.Generate()

	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Check simple type (no attributes)
	if !strings.Contains(result, "type simple_t;") {
		t.Error("Missing simple_t type declaration")
	}

	// Check type with single attribute
	if !strings.Contains(result, "type domain_t, domain;") {
		t.Error("Missing or incorrect domain_t type declaration")
	}

	// Check type with multiple attributes
	if !strings.Contains(result, "type file_t, file_type, data_file_type;") {
		t.Error("Missing or incorrect file_t type declaration")
	}
}

// TestTEGenerator_AllowRules tests allow rule generation and grouping
func TestTEGenerator_AllowRules(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName: "test",
		Version:    "1.0.0",
		Types: []models.TypeDeclaration{
			{TypeName: "httpd_t"},
			{TypeName: "httpd_sys_content_t"},
		},
		Rules: []models.AllowRule{
			{
				SourceType:  "httpd_t",
				TargetType:  "httpd_sys_content_t",
				Class:       "file",
				Permissions: []string{"read"},
			},
			{
				SourceType:  "httpd_t",
				TargetType:  "httpd_sys_content_t",
				Class:       "file",
				Permissions: []string{"open", "getattr"},
			},
			{
				SourceType:  "httpd_t",
				TargetType:  "httpd_sys_content_t",
				Class:       "dir",
				Permissions: []string{"search", "read"},
			},
		},
	}

	generator := NewTEGenerator(policy)
	result, err := generator.Generate()

	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Check allow rules section
	if !strings.Contains(result, "# Allow Rules") {
		t.Error("Missing Allow Rules section")
	}

	// Check that file permissions are grouped together
	// Should have one rule with { read open getattr } or some permutation
	if !strings.Contains(result, "allow httpd_t httpd_sys_content_t:file") {
		t.Error("Missing file allow rule")
	}

	// Check dir rule
	if !strings.Contains(result, "allow httpd_t httpd_sys_content_t:dir") {
		t.Error("Missing dir allow rule")
	}

	// Verify permissions are merged
	lines := strings.Split(result, "\n")
	fileRuleCount := 0
	for _, line := range lines {
		if strings.Contains(line, "allow httpd_t httpd_sys_content_t:file") {
			fileRuleCount++
		}
	}

	if fileRuleCount != 1 {
		t.Errorf("File permissions should be merged into one rule, got %d rules", fileRuleCount)
	}
}

// TestTEGenerator_DenyRules tests neverallow rule generation
func TestTEGenerator_DenyRules(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName: "test",
		Version:    "1.0.0",
		DenyRules: []models.DenyRule{
			{
				SourceType:  "user_t",
				TargetType:  "shadow_t",
				Class:       "file",
				Permissions: []string{"read", "write"},
			},
			{
				SourceType:  "guest_t",
				TargetType:  "admin_home_t",
				Class:       "dir",
				Permissions: []string{"write"},
			},
		},
	}

	generator := NewTEGenerator(policy)
	result, err := generator.Generate()

	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Check deny rules section
	if !strings.Contains(result, "# Deny Rules (neverallow)") {
		t.Error("Missing Deny Rules section")
	}

	// Check neverallow rules
	if !strings.Contains(result, "neverallow user_t shadow_t:file { read write }") &&
		!strings.Contains(result, "neverallow user_t shadow_t:file { write read }") {
		t.Error("Missing or incorrect neverallow rule for user_t")
	}

	if !strings.Contains(result, "neverallow guest_t admin_home_t:dir write;") {
		t.Error("Missing neverallow rule for guest_t")
	}
}

// TestTEGenerator_TypeTransitions tests type_transition generation
func TestTEGenerator_TypeTransitions(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName: "test",
		Version:    "1.0.0",
		Transitions: []models.TypeTransition{
			{
				SourceType: "httpd_t",
				TargetType: "tmp_t",
				Class:      "file",
				NewType:    "httpd_tmp_t",
			},
			{
				SourceType: "init_t",
				TargetType: "httpd_exec_t",
				Class:      "process",
				NewType:    "httpd_t",
			},
		},
	}

	generator := NewTEGenerator(policy)
	result, err := generator.Generate()

	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Check type transitions section
	if !strings.Contains(result, "# Type Transitions") {
		t.Error("Missing Type Transitions section")
	}

	// Check transition rules
	if !strings.Contains(result, "type_transition httpd_t tmp_t:file httpd_tmp_t;") {
		t.Error("Missing file type_transition")
	}

	if !strings.Contains(result, "type_transition init_t httpd_exec_t:process httpd_t;") {
		t.Error("Missing process type_transition (domain transition)")
	}
}

// TestTEGenerator_SortedOutput tests that output is consistently sorted
func TestTEGenerator_SortedOutput(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName: "test",
		Version:    "1.0.0",
		Types: []models.TypeDeclaration{
			{TypeName: "ztype_t"},
			{TypeName: "atype_t"},
			{TypeName: "mtype_t"},
		},
		Booleans: []models.BooleanDeclaration{
			{Name: "zboolean", DefaultValue: false},
			{Name: "aboolean", DefaultValue: true},
		},
	}

	generator := NewTEGenerator(policy)
	result, err := generator.Generate()

	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Find positions of types (should be sorted alphabetically)
	atypeIdx := strings.Index(result, "type atype_t;")
	mtypeIdx := strings.Index(result, "type mtype_t;")
	ztypeIdx := strings.Index(result, "type ztype_t;")

	if atypeIdx == -1 || mtypeIdx == -1 || ztypeIdx == -1 {
		t.Fatal("Missing type declarations")
	}

	if !(atypeIdx < mtypeIdx && mtypeIdx < ztypeIdx) {
		t.Error("Types not sorted alphabetically")
	}

	// Find positions of booleans (should be sorted alphabetically)
	aboolIdx := strings.Index(result, "gen_tunable(aboolean")
	zboolIdx := strings.Index(result, "gen_tunable(zboolean")

	if aboolIdx == -1 || zboolIdx == -1 {
		t.Fatal("Missing boolean declarations")
	}

	if aboolIdx >= zboolIdx {
		t.Error("Booleans not sorted alphabetically")
	}
}

// TestTEGenerator_ComplexPolicy tests a realistic complex policy
func TestTEGenerator_ComplexPolicy(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName: "httpd",
		Version:    "1.0.0",
		Booleans: []models.BooleanDeclaration{
			{
				Name:         "httpd_enable_homedirs",
				DefaultValue: false,
				Description:  "Allow httpd to read user home directories",
			},
		},
		Types: []models.TypeDeclaration{
			{TypeName: "httpd_t", Attributes: []string{"domain"}},
			{TypeName: "httpd_exec_t", Attributes: []string{"file_type", "exec_type"}},
			{TypeName: "httpd_sys_content_t", Attributes: []string{"file_type"}},
			{TypeName: "httpd_tmp_t", Attributes: []string{"file_type"}},
		},
		Rules: []models.AllowRule{
			{
				SourceType:  "httpd_t",
				TargetType:  "httpd_sys_content_t",
				Class:       "file",
				Permissions: []string{"read", "getattr", "open"},
			},
			{
				SourceType:  "httpd_t",
				TargetType:  "httpd_sys_content_t",
				Class:       "dir",
				Permissions: []string{"search", "getattr"},
			},
		},
		Transitions: []models.TypeTransition{
			{
				SourceType: "httpd_t",
				TargetType: "tmp_t",
				Class:      "file",
				NewType:    "httpd_tmp_t",
			},
		},
	}

	generator := NewTEGenerator(policy)
	result, err := generator.Generate()

	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Check all sections are present
	sections := []string{
		"policy_module(httpd, 1.0.0)",
		"# Boolean Declarations",
		"gen_tunable(httpd_enable_homedirs, false)",
		"# Type Declarations",
		"type httpd_t, domain;",
		"# Allow Rules",
		"allow httpd_t httpd_sys_content_t:file",
		"# Type Transitions",
		"type_transition httpd_t tmp_t:file httpd_tmp_t;",
	}

	for _, section := range sections {
		if !strings.Contains(result, section) {
			t.Errorf("Missing expected section or content: %s", section)
		}
	}
}

// TestGenerateTE tests the convenience function
func TestGenerateTE(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName: "test",
		Version:    "1.0.0",
		Types: []models.TypeDeclaration{
			{TypeName: "test_t"},
		},
	}

	result, err := GenerateTE(policy)

	if err != nil {
		t.Fatalf("GenerateTE() error = %v", err)
	}

	if !strings.Contains(result, "policy_module(test, 1.0.0)") {
		t.Error("GenerateTE() should contain policy_module declaration")
	}

	if !strings.Contains(result, "type test_t;") {
		t.Error("GenerateTE() should contain type declaration")
	}
}

// TestTEGenerator_ConditionalBlocks tests conditional policy generation
func TestTEGenerator_ConditionalBlocks(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName: "httpd",
		Version:    "1.0.0",
		Booleans: []models.BooleanDeclaration{
			{
				Name:         "httpd_enable_homedirs",
				DefaultValue: false,
			},
		},
		ConditionalBlocks: []models.ConditionalBlock{
			{
				BooleanExpr: "httpd_enable_homedirs",
				ThenRules: []models.AllowRule{
					{
						SourceType:  "httpd_t",
						TargetType:  "user_home_t",
						Class:       "file",
						Permissions: []string{"read", "open"},
					},
				},
			},
		},
	}

	generator := NewTEGenerator(policy)
	result, err := generator.Generate()

	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Check conditional block section
	if !strings.Contains(result, "# Conditional Policy Blocks") {
		t.Error("Missing Conditional Policy Blocks section")
	}

	// Check if statement
	if !strings.Contains(result, "if (httpd_enable_homedirs) {") {
		t.Error("Missing if statement")
	}

	// Check allow rule inside if block
	if !strings.Contains(result, "allow httpd_t user_home_t:file") {
		t.Error("Missing allow rule in conditional block")
	}

	// Check closing brace
	if !strings.Contains(result, "}") {
		t.Error("Missing closing brace for conditional block")
	}
}

// TestTEGenerator_ConditionalWithElse tests if-else generation
func TestTEGenerator_ConditionalWithElse(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName: "test",
		Version:    "1.0.0",
		ConditionalBlocks: []models.ConditionalBlock{
			{
				BooleanExpr: "test_boolean",
				ThenRules: []models.AllowRule{
					{
						SourceType:  "test_t",
						TargetType:  "allowed_t",
						Class:       "file",
						Permissions: []string{"read"},
					},
				},
				ElseRules: []models.AllowRule{
					{
						SourceType:  "test_t",
						TargetType:  "default_t",
						Class:       "file",
						Permissions: []string{"read"},
					},
				},
			},
		},
	}

	generator := NewTEGenerator(policy)
	result, err := generator.Generate()

	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Check if-else structure
	if !strings.Contains(result, "if (test_boolean) {") {
		t.Error("Missing if statement")
	}
	if !strings.Contains(result, "} else {") {
		t.Error("Missing else clause")
	}

	// Check then rule
	if !strings.Contains(result, "allow test_t allowed_t:file read;") {
		t.Error("Missing then rule")
	}

	// Check else rule
	if !strings.Contains(result, "allow test_t default_t:file read;") {
		t.Error("Missing else rule")
	}
}

// TestTEGenerator_NegatedBoolean tests negated boolean expressions
func TestTEGenerator_NegatedBoolean(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName: "test",
		Version:    "1.0.0",
		ConditionalBlocks: []models.ConditionalBlock{
			{
				BooleanExpr: "!allow_feature",
				ThenRules: []models.AllowRule{
					{
						SourceType:  "test_t",
						TargetType:  "restricted_t",
						Class:       "file",
						Permissions: []string{"read"},
					},
				},
			},
		},
	}

	generator := NewTEGenerator(policy)
	result, err := generator.Generate()

	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Check negated boolean
	if !strings.Contains(result, "if (!allow_feature) {") {
		t.Error("Missing negated boolean expression")
	}
}

// TestTEGenerator_DomainTransition tests complete domain transition triplet generation
func TestTEGenerator_DomainTransition(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName: "test",
		Version:    "1.0.0",
		Transitions: []models.TypeTransition{
			{
				SourceType: "init_t",
				TargetType: "httpd_exec_t",
				Class:      "process",
				NewType:    "httpd_t",
			},
		},
	}

	generator := NewTEGenerator(policy)
	result, err := generator.Generate()

	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Check domain transition comment
	if !strings.Contains(result, "# Domain transition: init_t -> httpd_t") {
		t.Error("Missing domain transition comment")
	}

	// Check type_transition rule
	if !strings.Contains(result, "type_transition init_t httpd_exec_t:process httpd_t;") {
		t.Error("Missing type_transition rule")
	}

	// Check execute permission
	if !strings.Contains(result, "allow init_t httpd_exec_t:file execute;") {
		t.Error("Missing execute permission")
	}

	// Check transition permission
	if !strings.Contains(result, "allow init_t httpd_t:process transition;") {
		t.Error("Missing transition permission")
	}

	// Check entrypoint permission
	if !strings.Contains(result, "allow httpd_t httpd_exec_t:file entrypoint;") {
		t.Error("Missing entrypoint permission")
	}
}

// TestTEGenerator_RegularTypeTransition tests non-domain transitions
func TestTEGenerator_RegularTypeTransition(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName: "test",
		Version:    "1.0.0",
		Transitions: []models.TypeTransition{
			{
				SourceType: "httpd_t",
				TargetType: "tmp_t",
				Class:      "file",
				NewType:    "httpd_tmp_t",
			},
		},
	}

	generator := NewTEGenerator(policy)
	result, err := generator.Generate()

	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Check regular type transition (no triplet)
	if !strings.Contains(result, "type_transition httpd_t tmp_t:file httpd_tmp_t;") {
		t.Error("Missing regular type transition")
	}

	// Should not have domain transition rules
	if strings.Contains(result, "execute") {
		t.Error("Regular transition should not have execute permission")
	}
	if strings.Contains(result, "entrypoint") {
		t.Error("Regular transition should not have entrypoint permission")
	}
}

// TestTEGenerator_MixedTransitions tests both domain and regular transitions
func TestTEGenerator_MixedTransitions(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName: "test",
		Version:    "1.0.0",
		Transitions: []models.TypeTransition{
			{
				SourceType: "init_t",
				TargetType: "sshd_exec_t",
				Class:      "process",
				NewType:    "sshd_t",
			},
			{
				SourceType: "sshd_t",
				TargetType: "tmp_t",
				Class:      "file",
				NewType:    "sshd_tmp_t",
			},
		},
	}

	generator := NewTEGenerator(policy)
	result, err := generator.Generate()

	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Check domain transition
	if !strings.Contains(result, "# Domain transition: init_t -> sshd_t") {
		t.Error("Missing domain transition")
	}
	if !strings.Contains(result, "allow init_t sshd_exec_t:file execute;") {
		t.Error("Missing domain transition rules")
	}

	// Check regular transition
	if !strings.Contains(result, "type_transition sshd_t tmp_t:file sshd_tmp_t;") {
		t.Error("Missing regular type transition")
	}
}
