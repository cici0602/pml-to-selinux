package selinux

import (
	"strings"
	"testing"

	"github.com/cici0602/pml-to-selinux/models"
)

func TestIFGenerator_Generate(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName: "testapp",
		Types: []models.TypeDeclaration{
			{TypeName: "testapp_t"},
			{TypeName: "testapp_log_t"},
			{TypeName: "testapp_exec_t"},
		},
		Rules: []models.AllowRule{
			{
				SourceType:  "testapp_t",
				TargetType:  "testapp_log_t",
				Class:       "file",
				Permissions: []string{"read", "write", "open"},
			},
			{
				SourceType:  "testapp_t",
				TargetType:  "testapp_exec_t",
				Class:       "file",
				Permissions: []string{"execute", "execute_no_trans"},
			},
		},
		Transitions: []models.TypeTransition{
			{
				SourceType: "testapp_t",
				TargetType: "tmp_t",
				Class:      "file",
				NewType:    "testapp_tmp_t",
			},
		},
	}

	generator := NewIFGenerator(policy)
	content, err := generator.Generate()

	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Check for basic structure
	if !strings.Contains(content, "testapp policy module") {
		t.Error("Generated .if file missing module description")
	}

	if !strings.Contains(content, "testapp_read_files") {
		t.Error("Generated .if file missing read interface")
	}

	if !strings.Contains(content, "testapp_write_files") {
		t.Error("Generated .if file missing write interface")
	}

	if !strings.Contains(content, "testapp_exec") {
		t.Error("Generated .if file missing exec interface")
	}

	if !strings.Contains(content, "testapp_domtrans") {
		t.Error("Generated .if file missing domain transition interface")
	}
}

func TestIFGenerator_EmptyPolicy(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName: "empty",
		Types:      []models.TypeDeclaration{},
		Rules:      []models.AllowRule{},
	}

	generator := NewIFGenerator(policy)
	content, err := generator.Generate()

	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Should still generate header
	if !strings.Contains(content, "empty policy module") {
		t.Error("Generated .if file missing module description")
	}
}

func TestIFGenerator_PermissionHelpers(t *testing.T) {
	tests := []struct {
		name      string
		perms     []string
		wantRead  bool
		wantWrite bool
		wantExec  bool
	}{
		{"read permissions", []string{"read", "open"}, true, false, false},
		{"write permissions", []string{"write", "append"}, false, true, false},
		{"execute permissions", []string{"execute"}, false, false, true},
		{"mixed permissions", []string{"read", "write"}, true, true, false},
		{"no special permissions", []string{"ioctl"}, false, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasReadPerm(tt.perms); got != tt.wantRead {
				t.Errorf("hasReadPerm() = %v, want %v", got, tt.wantRead)
			}
			if got := hasWritePerm(tt.perms); got != tt.wantWrite {
				t.Errorf("hasWritePerm() = %v, want %v", got, tt.wantWrite)
			}
			if got := hasExecutePerm(tt.perms); got != tt.wantExec {
				t.Errorf("hasExecutePerm() = %v, want %v", got, tt.wantExec)
			}
		})
	}
}
