package mapping

import (
	"strings"
	"testing"

	"github.com/cici0602/pml-to-selinux/models"
)

func TestFilesystemMapper_GenerateGenfsconRules(t *testing.T) {
	fm := NewFilesystemMapper()

	rules := fm.GenerateGenfsconRules()

	if len(rules) == 0 {
		t.Error("GenerateGenfsconRules() returned no rules")
	}

	// Check for essential filesystem rules
	foundProc := false
	foundSysfs := false
	foundSelinuxfs := false

	for _, rule := range rules {
		switch rule.FSType {
		case "proc":
			foundProc = true
		case "sysfs":
			foundSysfs = true
		case "selinuxfs":
			foundSelinuxfs = true
		}
	}

	if !foundProc {
		t.Error("Missing proc filesystem rules")
	}
	if !foundSysfs {
		t.Error("Missing sysfs filesystem rules")
	}
	if !foundSelinuxfs {
		t.Error("Missing selinuxfs filesystem rules")
	}
}

func TestFilesystemMapper_GenerateFsuseRules(t *testing.T) {
	fm := NewFilesystemMapper()

	rules := fm.GenerateFsuseRules()

	if len(rules) == 0 {
		t.Error("GenerateFsuseRules() returned no rules")
	}

	// Check for different use types
	foundXattr := false
	foundTrans := false
	foundTask := false

	for _, rule := range rules {
		switch rule.UseType {
		case "xattr":
			foundXattr = true
		case "trans":
			foundTrans = true
		case "task":
			foundTask = true
		}
	}

	if !foundXattr {
		t.Error("Missing xattr filesystem rules")
	}
	if !foundTrans {
		t.Error("Missing trans filesystem rules")
	}
	if !foundTask {
		t.Error("Missing task filesystem rules")
	}
}

func TestFilesystemMapper_InferFSType(t *testing.T) {
	fm := NewFilesystemMapper()

	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "proc filesystem",
			path:     "/proc/cpuinfo",
			expected: "proc",
		},
		{
			name:     "sysfs filesystem",
			path:     "/sys/devices",
			expected: "sysfs",
		},
		{
			name:     "devpts filesystem",
			path:     "/dev/pts/0",
			expected: "devpts",
		},
		{
			name:     "tmpfs filesystem",
			path:     "/tmp/file",
			expected: "tmpfs",
		},
		{
			name:     "selinuxfs filesystem",
			path:     "/sys/fs/selinux/enforce",
			expected: "selinuxfs",
		},
		{
			name:     "default filesystem",
			path:     "/var/www/html",
			expected: "ext4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := fm.InferFSType(tt.path)
			if result != tt.expected {
				t.Errorf("InferFSType() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestFilesystemMapper_GetFilesystemSecurity(t *testing.T) {
	fm := NewFilesystemMapper()

	tests := []struct {
		name               string
		fsType             string
		wantXattr          bool
		wantLabels         bool
		wantDefaultUseType string
	}{
		{
			name:               "ext4 filesystem",
			fsType:             "ext4",
			wantXattr:          true,
			wantLabels:         true,
			wantDefaultUseType: "xattr",
		},
		{
			name:               "tmpfs filesystem",
			fsType:             "tmpfs",
			wantXattr:          false,
			wantLabels:         true,
			wantDefaultUseType: "trans",
		},
		{
			name:               "proc filesystem",
			fsType:             "proc",
			wantXattr:          false,
			wantLabels:         true,
			wantDefaultUseType: "task",
		},
		{
			name:               "nfs filesystem",
			fsType:             "nfs",
			wantXattr:          false,
			wantLabels:         false,
			wantDefaultUseType: "trans",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sec := fm.GetFilesystemSecurity(tt.fsType)
			if sec.SupportsXattr != tt.wantXattr {
				t.Errorf("SupportsXattr = %v, want %v", sec.SupportsXattr, tt.wantXattr)
			}
			if sec.SupportsLabels != tt.wantLabels {
				t.Errorf("SupportsLabels = %v, want %v", sec.SupportsLabels, tt.wantLabels)
			}
			if sec.DefaultUseType != tt.wantDefaultUseType {
				t.Errorf("DefaultUseType = %v, want %v", sec.DefaultUseType, tt.wantDefaultUseType)
			}
		})
	}
}

func TestFilesystemMapper_ValidateFilesystemPolicy(t *testing.T) {
	fm := NewFilesystemMapper()

	tests := []struct {
		name          string
		genfsconRules []GenfsconRule
		fsuseRules    []FsuseRule
		wantErrors    bool
	}{
		{
			name: "valid rules",
			genfsconRules: []GenfsconRule{
				{FSType: "proc", Path: "/", Context: "system_u:object_r:proc_t:s0"},
			},
			fsuseRules: []FsuseRule{
				{UseType: "xattr", FSType: "ext4", Context: "system_u:object_r:fs_t:s0"},
			},
			wantErrors: false,
		},
		{
			name: "duplicate genfscon rules",
			genfsconRules: []GenfsconRule{
				{FSType: "proc", Path: "/", Context: "system_u:object_r:proc_t:s0"},
				{FSType: "proc", Path: "/", Context: "system_u:object_r:proc_t:s0"},
			},
			fsuseRules: []FsuseRule{},
			wantErrors: true,
		},
		{
			name: "invalid context format",
			genfsconRules: []GenfsconRule{
				{FSType: "proc", Path: "/", Context: "invalid_context"},
			},
			fsuseRules: []FsuseRule{},
			wantErrors: true,
		},
		{
			name:          "invalid fsuse type",
			genfsconRules: []GenfsconRule{},
			fsuseRules: []FsuseRule{
				{UseType: "invalid", FSType: "ext4", Context: "system_u:object_r:fs_t:s0"},
			},
			wantErrors: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := fm.ValidateFilesystemPolicy(tt.genfsconRules, tt.fsuseRules)
			if (len(errors) > 0) != tt.wantErrors {
				t.Errorf("ValidateFilesystemPolicy() errors = %v, wantErrors %v", errors, tt.wantErrors)
			}
		})
	}
}

func TestFilesystemMapper_GeneratePortconRules(t *testing.T) {
	fm := NewFilesystemMapper()

	rules := fm.GeneratePortconRules()

	if len(rules) == 0 {
		t.Error("GeneratePortconRules() returned no rules")
	}

	// Check for common ports
	foundHTTP := false
	foundSSH := false
	foundDNS := false

	for _, rule := range rules {
		switch rule.Port {
		case 80, 443:
			foundHTTP = true
			if !strings.Contains(rule.Context, "http_port_t") {
				t.Errorf("HTTP port has wrong context: %s", rule.Context)
			}
		case 22:
			foundSSH = true
			if !strings.Contains(rule.Context, "ssh_port_t") {
				t.Errorf("SSH port has wrong context: %s", rule.Context)
			}
		case 53:
			foundDNS = true
			if !strings.Contains(rule.Context, "dns_port_t") {
				t.Errorf("DNS port has wrong context: %s", rule.Context)
			}
		}
	}

	if !foundHTTP {
		t.Error("Missing HTTP port rules")
	}
	if !foundSSH {
		t.Error("Missing SSH port rules")
	}
	if !foundDNS {
		t.Error("Missing DNS port rules")
	}
}

func TestFilesystemMapper_GenerateFilesystemContext(t *testing.T) {
	fm := NewFilesystemMapper()

	level := models.DefaultSecurityRange()
	context := fm.GenerateFilesystemContext("ext4", "/var/www", "httpd_sys_content_t", level)

	expected := "system_u:object_r:httpd_sys_content_t:s0"
	if context != expected {
		t.Errorf("GenerateFilesystemContext() = %v, want %v", context, expected)
	}
}
