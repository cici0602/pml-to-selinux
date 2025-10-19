package compiler

import (
	"testing"

	"github.com/cici0602/pml-to-selinux/models"
)

func TestDiffer_TypeChanges(t *testing.T) {
	policy1 := &models.SELinuxPolicy{
		Types: []models.TypeDeclaration{
			{TypeName: "httpd_t"},
			{TypeName: "httpd_log_t"},
		},
	}

	policy2 := &models.SELinuxPolicy{
		Types: []models.TypeDeclaration{
			{TypeName: "httpd_t"},
			{TypeName: "httpd_config_t"},
		},
	}

	differ := NewDiffer(policy1, policy2)
	result := differ.Diff()

	// httpd_log_t should be removed
	if len(result.TypesRemoved) != 1 || result.TypesRemoved[0] != "httpd_log_t" {
		t.Errorf("Expected httpd_log_t to be removed, got %v", result.TypesRemoved)
	}

	// httpd_config_t should be added
	if len(result.TypesAdded) != 1 || result.TypesAdded[0] != "httpd_config_t" {
		t.Errorf("Expected httpd_config_t to be added, got %v", result.TypesAdded)
	}
}

func TestDiffer_RuleChanges(t *testing.T) {
	policy1 := &models.SELinuxPolicy{
		Rules: []models.AllowRule{
			{
				SourceType:  "httpd_t",
				TargetType:  "httpd_log_t",
				Class:       "file",
				Permissions: []string{"read", "write"},
			},
		},
	}

	policy2 := &models.SELinuxPolicy{
		Rules: []models.AllowRule{
			{
				SourceType:  "httpd_t",
				TargetType:  "httpd_config_t",
				Class:       "file",
				Permissions: []string{"read"},
			},
		},
	}

	differ := NewDiffer(policy1, policy2)
	result := differ.Diff()

	// Old rule should be removed
	if len(result.RulesRemoved) != 1 {
		t.Errorf("Expected 1 rule removed, got %d", len(result.RulesRemoved))
	}

	// New rule should be added
	if len(result.RulesAdded) != 1 {
		t.Errorf("Expected 1 rule added, got %d", len(result.RulesAdded))
	}
}

func TestDiffer_NoDifferences(t *testing.T) {
	policy := &models.SELinuxPolicy{
		Types: []models.TypeDeclaration{
			{TypeName: "httpd_t"},
		},
		Rules: []models.AllowRule{
			{
				SourceType:  "httpd_t",
				TargetType:  "httpd_log_t",
				Class:       "file",
				Permissions: []string{"read"},
			},
		},
	}

	differ := NewDiffer(policy, policy)
	result := differ.Diff()

	if len(result.TypesAdded) > 0 || len(result.TypesRemoved) > 0 {
		t.Error("Expected no type differences for identical policies")
	}

	if len(result.RulesAdded) > 0 || len(result.RulesRemoved) > 0 {
		t.Error("Expected no rule differences for identical policies")
	}
}

func TestFormatDiff_EmptyResult(t *testing.T) {
	result := &DiffResult{}
	output := FormatDiff(result)

	if output != "No differences found.\n" {
		t.Errorf("Expected 'No differences found.' message, got: %s", output)
	}
}

func TestFormatDiff_WithChanges(t *testing.T) {
	result := &DiffResult{
		TypesAdded:   []string{"new_type_t"},
		TypesRemoved: []string{"old_type_t"},
		RulesAdded:   []string{"allow new_t file_t:file read"},
	}

	output := FormatDiff(result)

	if len(output) == 0 {
		t.Error("Expected non-empty diff output")
	}
}
