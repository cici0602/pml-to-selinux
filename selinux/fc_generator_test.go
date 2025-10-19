package selinux

import (
	"strings"
	"testing"

	"github.com/cici0602/pml-to-selinux/models"
)

func TestFCGenerator_Generate(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName: "httpd",
		Version:    "1.0.0",
		FileContexts: []models.FileContext{
			{
				PathPattern: "/var/www/html(/.*)?",
				FileType:    "--",
				SELinuxType: "httpd_sys_content_t",
			},
			{
				PathPattern: "/etc/httpd/conf/httpd\\.conf",
				FileType:    "--",
				SELinuxType: "httpd_config_t",
			},
		},
	}

	generator := NewFCGenerator(policy)
	result, err := generator.Generate()

	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "# SELinux File Contexts: httpd") {
		t.Error("Missing module name in header")
	}

	if !strings.Contains(result, "gen_context(system_u:object_r:httpd_sys_content_t:s0)") {
		t.Error("Missing or malformed gen_context for httpd_sys_content_t")
	}
}

func TestFCGenerator_EmptyPolicy(t *testing.T) {
	policy := &models.SELinuxPolicy{
		ModuleName:   "empty",
		Version:      "1.0.0",
		FileContexts: []models.FileContext{},
	}

	generator := NewFCGenerator(policy)
	result, err := generator.Generate()

	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if !strings.Contains(result, "# SELinux File Contexts: empty") {
		t.Error("Missing header")
	}

	if strings.Contains(result, "gen_context") {
		t.Error("Should not contain gen_context for empty policy")
	}
}
