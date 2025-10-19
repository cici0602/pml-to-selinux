package mapping

import (
	"testing"
)

// TestFilesystemMapper_GenerateGenfsconRules tests genfscon rule generation
func TestFilesystemMapper_GenerateGenfsconRules(t *testing.T) {
	fm := NewFilesystemMapper()

	rules := fm.GenerateGenfsconRules()

	if len(rules) == 0 {
		t.Error("Expected non-empty genfscon rules")
	}

	// Check for common filesystem types
	expectedFSTypes := []string{"proc", "sysfs", "selinuxfs", "tmpfs", "devpts"}
	for _, expectedFS := range expectedFSTypes {
		found := false
		for _, rule := range rules {
			if rule.FSType == expectedFS {
				found = true
				// Validate context format
				if rule.Context == "" {
					t.Errorf("Empty context for filesystem %s", expectedFS)
				}
				break
			}
		}
		if !found {
			t.Errorf("Expected filesystem type %s not found in genfscon rules", expectedFS)
		}
	}
}

// TestFilesystemMapper_GenerateFsuseRules tests fs_use rule generation
func TestFilesystemMapper_GenerateFsuseRules(t *testing.T) {
	fm := NewFilesystemMapper()

	rules := fm.GenerateFsuseRules()

	if len(rules) == 0 {
		t.Error("Expected non-empty fsuse rules")
	}

	// Check for xattr filesystems
	xattrFS := []string{"ext2", "ext3", "ext4", "xfs", "btrfs"}
	for _, fs := range xattrFS {
		found := false
		for _, rule := range rules {
			if rule.FSType == fs && rule.UseType == "xattr" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected xattr filesystem %s not found in fsuse rules", fs)
		}
	}

	// Check for trans filesystems
	transFS := []string{"tmpfs", "devpts", "mqueue"}
	for _, fs := range transFS {
		found := false
		for _, rule := range rules {
			if rule.FSType == fs && rule.UseType == "trans" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected trans filesystem %s not found in fsuse rules", fs)
		}
	}

	// Check for task filesystems
	taskFS := []string{"proc", "sysfs"}
	for _, fs := range taskFS {
		found := false
		for _, rule := range rules {
			if rule.FSType == fs && rule.UseType == "task" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected task filesystem %s not found in fsuse rules", fs)
		}
	}
}

// TestFilesystemMapper_InferFSType tests filesystem type inference
func TestFilesystemMapper_InferFSType(t *testing.T) {
	fm := NewFilesystemMapper()

	tests := []struct {
		path     string
		expected string
	}{
		{"/proc/cpuinfo", "proc"},
		{"/sys/devices", "sysfs"},
		{"/selinux/enforce", "selinuxfs"},
		{"/sys/fs/selinux/enforce", "selinuxfs"},
		{"/dev/pts/0", "devpts"},
		{"/dev/shm/test", "tmpfs"},
		{"/run/systemd", "tmpfs"},
		{"/tmp/test", "tmpfs"},
		{"/var/www/html", "ext4"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := fm.InferFSType(tt.path)
			if result != tt.expected {
				t.Errorf("InferFSType(%q) = %q, want %q",
					tt.path, result, tt.expected)
			}
		})
	}
}

// TestFilesystemMapper_GenerateFilesystemContext tests context generation
func TestFilesystemMapper_GenerateFilesystemContext(t *testing.T) {
	fm := NewFilesystemMapper()

	tests := []struct {
		name     string
		fsType   string
		path     string
		typeName string
		level    string
		expected string
	}{
		{
			name:     "basic context",
			fsType:   "ext4",
			path:     "/var/www",
			typeName: "httpd_sys_content_t",
			level:    "s0",
			expected: "system_u:object_r:httpd_sys_content_t:s0",
		},
		{
			name:     "default level",
			fsType:   "ext4",
			path:     "/etc",
			typeName: "etc_t",
			level:    "",
			expected: "system_u:object_r:etc_t:s0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := fm.GenerateFilesystemContext(tt.fsType, tt.path, tt.typeName, tt.level)
			if result != tt.expected {
				t.Errorf("GenerateFilesystemContext() = %q, want %q",
					result, tt.expected)
			}
		})
	}
}

// TestFilesystemMapper_GetFilesystemSecurity tests filesystem security properties
func TestFilesystemMapper_GetFilesystemSecurity(t *testing.T) {
	fm := NewFilesystemMapper()

	tests := []struct {
		fsType                string
		expectedSupportsXattr bool
		expectedUseType       string
	}{
		{"ext4", true, "xattr"},
		{"xfs", true, "xattr"},
		{"btrfs", true, "xattr"},
		{"tmpfs", false, "trans"},
		{"devpts", false, "trans"},
		{"proc", false, "task"},
		{"sysfs", false, "task"},
		{"selinuxfs", false, "genfs"},
		{"nfs", false, "trans"},
	}

	for _, tt := range tests {
		t.Run(tt.fsType, func(t *testing.T) {
			result := fm.GetFilesystemSecurity(tt.fsType)

			if result.SupportsXattr != tt.expectedSupportsXattr {
				t.Errorf("GetFilesystemSecurity(%q).SupportsXattr = %v, want %v",
					tt.fsType, result.SupportsXattr, tt.expectedSupportsXattr)
			}

			if result.DefaultUseType != tt.expectedUseType {
				t.Errorf("GetFilesystemSecurity(%q).DefaultUseType = %q, want %q",
					tt.fsType, result.DefaultUseType, tt.expectedUseType)
			}
		})
	}
}

// TestFilesystemMapper_ValidateFilesystemPolicy tests policy validation
func TestFilesystemMapper_ValidateFilesystemPolicy(t *testing.T) {
	fm := NewFilesystemMapper()

	tests := []struct {
		name          string
		genfsconRules []GenfsconRule
		fsuseRules    []FsuseRule
		expectErrors  bool
	}{
		{
			name: "valid rules",
			genfsconRules: []GenfsconRule{
				{FSType: "proc", Path: "/", Context: "system_u:object_r:proc_t:s0"},
			},
			fsuseRules: []FsuseRule{
				{UseType: "xattr", FSType: "ext4", Context: "system_u:object_r:fs_t:s0"},
			},
			expectErrors: false,
		},
		{
			name: "duplicate genfscon",
			genfsconRules: []GenfsconRule{
				{FSType: "proc", Path: "/", Context: "system_u:object_r:proc_t:s0"},
				{FSType: "proc", Path: "/", Context: "system_u:object_r:proc_t:s0"},
			},
			fsuseRules:   []FsuseRule{},
			expectErrors: true,
		},
		{
			name: "invalid context format",
			genfsconRules: []GenfsconRule{
				{FSType: "proc", Path: "/", Context: "invalid_context"},
			},
			fsuseRules:   []FsuseRule{},
			expectErrors: true,
		},
		{
			name:          "invalid fsuse type",
			genfsconRules: []GenfsconRule{},
			fsuseRules: []FsuseRule{
				{UseType: "invalid", FSType: "ext4", Context: "system_u:object_r:fs_t:s0"},
			},
			expectErrors: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := fm.ValidateFilesystemPolicy(tt.genfsconRules, tt.fsuseRules)

			if tt.expectErrors && len(errors) == 0 {
				t.Error("Expected errors but got none")
			}

			if !tt.expectErrors && len(errors) > 0 {
				t.Errorf("Expected no errors but got: %v", errors)
			}
		})
	}
}

// TestFilesystemMapper_GeneratePortconRules tests portcon rule generation
func TestFilesystemMapper_GeneratePortconRules(t *testing.T) {
	fm := NewFilesystemMapper()

	rules := fm.GeneratePortconRules()

	if len(rules) == 0 {
		t.Error("Expected non-empty portcon rules")
	}

	// Check for common ports
	expectedPorts := map[int]string{
		80:   "http_port_t",
		443:  "http_port_t",
		22:   "ssh_port_t",
		53:   "dns_port_t",
		3306: "mysqld_port_t",
	}

	for port, expectedType := range expectedPorts {
		found := false
		for _, rule := range rules {
			if rule.Port == port {
				found = true
				if rule.Context == "" {
					t.Errorf("Empty context for port %d", port)
				}
				// Check that context contains expected type
				if !containsStr(rule.Context, expectedType) {
					t.Errorf("Port %d context %q doesn't contain expected type %q",
						port, rule.Context, expectedType)
				}
				break
			}
		}
		if !found {
			t.Errorf("Expected port %d not found in portcon rules", port)
		}
	}
}

// TestGenfsconRule_Format tests genfscon rule formatting
func TestGenfsconRule_Format(t *testing.T) {
	rule := GenfsconRule{
		FSType:  "proc",
		Path:    "/cpuinfo",
		Context: "system_u:object_r:proc_cpuinfo_t:s0",
	}

	// Just verify the struct is valid
	if rule.FSType == "" || rule.Path == "" || rule.Context == "" {
		t.Error("GenfsconRule has empty required fields")
	}
}

// TestFsuseRule_Format tests fsuse rule formatting
func TestFsuseRule_Format(t *testing.T) {
	rule := FsuseRule{
		UseType: "xattr",
		FSType:  "ext4",
		Context: "system_u:object_r:fs_t:s0",
	}

	// Verify struct validity
	if rule.UseType == "" || rule.FSType == "" || rule.Context == "" {
		t.Error("FsuseRule has empty required fields")
	}

	// Verify use type is valid
	validUseTypes := []string{"xattr", "trans", "task"}
	found := false
	for _, valid := range validUseTypes {
		if rule.UseType == valid {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Invalid use type: %s", rule.UseType)
	}
}

// TestPortconRule_Format tests portcon rule formatting
func TestPortconRule_Format(t *testing.T) {
	rule := PortconRule{
		Protocol: "tcp",
		Port:     80,
		PortEnd:  0,
		Context:  "system_u:object_r:http_port_t:s0",
	}

	// Verify struct validity
	if rule.Protocol == "" || rule.Port == 0 || rule.Context == "" {
		t.Error("PortconRule has invalid fields")
	}

	// Verify protocol is valid
	if rule.Protocol != "tcp" && rule.Protocol != "udp" {
		t.Errorf("Invalid protocol: %s", rule.Protocol)
	}
}

// Helper function
func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) &&
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			containsStrMiddle(s, substr)))
}

func containsStrMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
