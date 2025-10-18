package mapping

import (
	"testing"

	"github.com/cici0602/pml-to-selinux/models"
)

func TestAutoTransitionMapper_InferAutoTransitions(t *testing.T) {
	tm := NewTypeMapper("test")
	am := NewActionMapper()
	atm := NewAutoTransitionMapper(tm, am)

	typeTransitions := []models.TypeTransition{
		{
			SourceType: "httpd_t",
			TargetType: "httpd_exec_t",
			Class:      "process",
			NewType:    "httpd_child_t",
		},
		{
			SourceType: "user_t",
			TargetType: "passwd_exec_t",
			Class:      "process",
			NewType:    "passwd_t",
		},
	}

	allowRules := []models.AllowRule{
		{
			SourceType:  "httpd_t",
			TargetType:  "httpd_exec_t",
			Class:       "file",
			Permissions: []string{"execute"},
		},
		{
			SourceType:  "user_t",
			TargetType:  "passwd_exec_t",
			Class:       "file",
			Permissions: []string{"execute"},
		},
	}

	autoRules := atm.InferAutoTransitions(typeTransitions, allowRules)

	if len(autoRules) == 0 {
		t.Error("InferAutoTransitions() returned no rules")
	}

	// Check that auto transitions were inferred
	foundHTTPD := false
	foundPasswd := false

	for _, rule := range autoRules {
		if rule.SourceDomain == "httpd_t" && rule.TargetDomain == "httpd_child_t" {
			foundHTTPD = true
			if !rule.AutoInferred {
				t.Error("httpd transition should be auto-inferred")
			}
		}
		if rule.SourceDomain == "user_t" && rule.TargetDomain == "passwd_t" {
			foundPasswd = true
		}
	}

	if !foundHTTPD {
		t.Error("Missing httpd auto transition")
	}
	if !foundPasswd {
		t.Error("Missing passwd auto transition")
	}
}

func TestAutoTransitionMapper_GenerateTransitionRules(t *testing.T) {
	tm := NewTypeMapper("test")
	am := NewActionMapper()
	atm := NewAutoTransitionMapper(tm, am)

	autoRule := AutoTransitionRule{
		SourceDomain: "httpd_t",
		TargetDomain: "httpd_child_t",
		EntryPoint:   "httpd_exec_t",
		AutoInferred: true,
	}

	allowRules, typeTransition, interfaceCalls := atm.GenerateTransitionRules(autoRule)

	// Check that we have the necessary allow rules
	if len(allowRules) < 3 {
		t.Errorf("GenerateTransitionRules() returned %d rules, want at least 3", len(allowRules))
	}

	// Check for essential rules
	foundExecute := false
	foundEntrypoint := false
	foundTransition := false

	for _, rule := range allowRules {
		if rule.SourceType == "httpd_t" && rule.TargetType == "httpd_exec_t" && rule.Class == "file" {
			foundExecute = true
		}
		if rule.SourceType == "httpd_child_t" && rule.TargetType == "httpd_exec_t" && rule.Class == "file" {
			foundEntrypoint = true
		}
		if rule.SourceType == "httpd_t" && rule.TargetType == "httpd_child_t" && rule.Class == "process" {
			foundTransition = true
		}
	}

	if !foundExecute {
		t.Error("Missing execute permission rule")
	}
	if !foundEntrypoint {
		t.Error("Missing entrypoint permission rule")
	}
	if !foundTransition {
		t.Error("Missing transition permission rule")
	}

	// Check type_transition rule
	if typeTransition.SourceType != "httpd_t" {
		t.Errorf("TypeTransition.SourceType = %v, want httpd_t", typeTransition.SourceType)
	}
	if typeTransition.NewType != "httpd_child_t" {
		t.Errorf("TypeTransition.NewType = %v, want httpd_child_t", typeTransition.NewType)
	}

	// Check interface calls
	if len(interfaceCalls) == 0 {
		t.Error("GenerateTransitionRules() returned no interface calls")
	}
}

func TestAutoTransitionMapper_ValidateTransitionPath(t *testing.T) {
	tm := NewTypeMapper("test")
	am := NewActionMapper()
	atm := NewAutoTransitionMapper(tm, am)

	transitions := []AutoTransitionRule{
		{SourceDomain: "user_t", TargetDomain: "staff_t"},
		{SourceDomain: "staff_t", TargetDomain: "sysadm_t"},
	}

	tests := []struct {
		name       string
		path       []string
		wantValid  bool
		wantReason string
	}{
		{
			name:      "valid single transition",
			path:      []string{"user_t", "staff_t"},
			wantValid: true,
		},
		{
			name:      "valid multi-step transition",
			path:      []string{"user_t", "staff_t", "sysadm_t"},
			wantValid: true,
		},
		{
			name:      "invalid transition",
			path:      []string{"user_t", "root_t"},
			wantValid: false,
		},
		{
			name:       "too short path",
			path:       []string{"user_t"},
			wantValid:  false,
			wantReason: "at least 2 domains",
		},
		{
			name:      "privilege escalation",
			path:      []string{"guest_t", "admin_t"},
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := atm.ValidateTransitionPath(tt.path, transitions)
			if result.Valid != tt.wantValid {
				t.Errorf("ValidateTransitionPath() Valid = %v, want %v", result.Valid, tt.wantValid)
			}
			if tt.wantReason != "" && result.Reason != tt.wantReason {
				// Check if reason contains expected substring
				if len(result.Reason) == 0 {
					t.Errorf("ValidateTransitionPath() Reason is empty, want containing %q", tt.wantReason)
				}
			}
		})
	}
}

func TestAutoTransitionMapper_IsExecutableType(t *testing.T) {
	tm := NewTypeMapper("test")
	am := NewActionMapper()
	atm := NewAutoTransitionMapper(tm, am)

	tests := []struct {
		name     string
		typeName string
		expected bool
	}{
		{
			name:     "exec_t suffix",
			typeName: "httpd_exec_t",
			expected: true,
		},
		{
			name:     "bin_t suffix",
			typeName: "user_bin_t",
			expected: true,
		},
		{
			name:     "cmd_t suffix",
			typeName: "admin_cmd_t",
			expected: true,
		},
		{
			name:     "program_t suffix",
			typeName: "custom_program_t",
			expected: true,
		},
		{
			name:     "non-executable type",
			typeName: "httpd_t",
			expected: false,
		},
		{
			name:     "data type",
			typeName: "httpd_var_lib_t",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := atm.isExecutableType(tt.typeName)
			if result != tt.expected {
				t.Errorf("isExecutableType() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestAutoTransitionMapper_IsPrivilegedDomain(t *testing.T) {
	tm := NewTypeMapper("test")
	am := NewActionMapper()
	atm := NewAutoTransitionMapper(tm, am)

	tests := []struct {
		name     string
		domain   string
		expected bool
	}{
		{
			name:     "admin domain",
			domain:   "admin_t",
			expected: true,
		},
		{
			name:     "sysadm domain",
			domain:   "sysadm_t",
			expected: true,
		},
		{
			name:     "root domain",
			domain:   "root_t",
			expected: true,
		},
		{
			name:     "user domain",
			domain:   "user_t",
			expected: false,
		},
		{
			name:     "httpd domain",
			domain:   "httpd_t",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := atm.isPrivilegedDomain(tt.domain)
			if result != tt.expected {
				t.Errorf("isPrivilegedDomain() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestAutoTransitionMapper_IsConfinedDomain(t *testing.T) {
	tm := NewTypeMapper("test")
	am := NewActionMapper()
	atm := NewAutoTransitionMapper(tm, am)

	tests := []struct {
		name     string
		domain   string
		expected bool
	}{
		{
			name:     "user domain",
			domain:   "user_t",
			expected: true,
		},
		{
			name:     "staff domain",
			domain:   "staff_t",
			expected: true,
		},
		{
			name:     "guest domain",
			domain:   "guest_t",
			expected: true,
		},
		{
			name:     "confined domain",
			domain:   "confined_app_t",
			expected: true,
		},
		{
			name:     "unconfined domain",
			domain:   "unconfined_t",
			expected: false,
		},
		{
			name:     "system domain",
			domain:   "system_t",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := atm.isConfinedDomain(tt.domain)
			if result != tt.expected {
				t.Errorf("isConfinedDomain() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestAutoTransitionMapper_BuildTransitionGraph(t *testing.T) {
	tm := NewTypeMapper("test")
	am := NewActionMapper()
	atm := NewAutoTransitionMapper(tm, am)

	rules := []AutoTransitionRule{
		{SourceDomain: "user_t", TargetDomain: "httpd_t", EntryPoint: "httpd_exec_t"},
		{SourceDomain: "httpd_t", TargetDomain: "httpd_child_t", EntryPoint: "httpd_exec_t"},
		{SourceDomain: "user_t", TargetDomain: "passwd_t", EntryPoint: "passwd_exec_t"},
	}

	graph := atm.BuildTransitionGraph(rules)

	// Check nodes
	if len(graph.Nodes) < 4 {
		t.Errorf("BuildTransitionGraph() returned %d nodes, want at least 4", len(graph.Nodes))
	}

	// Check edges
	if len(graph.Edges["user_t"]) != 2 {
		t.Errorf("user_t has %d edges, want 2", len(graph.Edges["user_t"]))
	}
	if len(graph.Edges["httpd_t"]) != 1 {
		t.Errorf("httpd_t has %d edges, want 1", len(graph.Edges["httpd_t"]))
	}
}

func TestAutoTransitionMapper_FindTransitionPath(t *testing.T) {
	tm := NewTypeMapper("test")
	am := NewActionMapper()
	atm := NewAutoTransitionMapper(tm, am)

	rules := []AutoTransitionRule{
		{SourceDomain: "user_t", TargetDomain: "staff_t"},
		{SourceDomain: "staff_t", TargetDomain: "sysadm_t"},
		{SourceDomain: "user_t", TargetDomain: "httpd_t"},
	}

	graph := atm.BuildTransitionGraph(rules)

	tests := []struct {
		name     string
		source   string
		target   string
		wantPath bool
	}{
		{
			name:     "direct path",
			source:   "user_t",
			target:   "staff_t",
			wantPath: true,
		},
		{
			name:     "indirect path",
			source:   "user_t",
			target:   "sysadm_t",
			wantPath: true,
		},
		{
			name:     "no path",
			source:   "httpd_t",
			target:   "sysadm_t",
			wantPath: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := atm.FindTransitionPath(graph, tt.source, tt.target)
			if (path != nil) != tt.wantPath {
				t.Errorf("FindTransitionPath() returned path = %v, wantPath %v", path, tt.wantPath)
			}
		})
	}
}

func TestAutoTransitionMapper_OptimizeTransitions(t *testing.T) {
	tm := NewTypeMapper("test")
	am := NewActionMapper()
	atm := NewAutoTransitionMapper(tm, am)

	rules := []AutoTransitionRule{
		{SourceDomain: "user_t", TargetDomain: "httpd_t", EntryPoint: "httpd_exec_t"},
		{SourceDomain: "user_t", TargetDomain: "httpd_t", EntryPoint: "httpd_exec_t"}, // Duplicate
		{SourceDomain: "user_t", TargetDomain: "passwd_t", EntryPoint: "passwd_exec_t"},
	}

	optimized := atm.OptimizeTransitions(rules)

	if len(optimized) != 2 {
		t.Errorf("OptimizeTransitions() returned %d rules, want 2", len(optimized))
	}
}
