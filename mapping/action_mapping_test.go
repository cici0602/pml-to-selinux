package mapping

import (
	"testing"
)

func TestMapAction(t *testing.T) {
	am := NewActionMapper()

	tests := []struct {
		name          string
		action        string
		objectClass   string
		expectedClass string
		expectedPerms []string
	}{
		{
			name:          "Read file",
			action:        "read",
			objectClass:   "",
			expectedClass: "file",
			expectedPerms: []string{"read", "open", "getattr"},
		},
		{
			name:          "Write file",
			action:        "write",
			objectClass:   "",
			expectedClass: "file",
			expectedPerms: []string{"write", "open", "append"},
		},
		{
			name:          "Execute file",
			action:        "execute",
			objectClass:   "",
			expectedClass: "file",
			expectedPerms: []string{"execute", "read", "open", "getattr", "execute_no_trans"},
		},
		{
			name:          "Search directory",
			action:        "search",
			objectClass:   "",
			expectedClass: "dir",
			expectedPerms: []string{"search", "getattr"},
		},
		{
			name:          "Network bind",
			action:        "bind",
			objectClass:   "",
			expectedClass: "tcp_socket",
			expectedPerms: []string{"bind"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			class, perms := am.MapAction(tt.action, tt.objectClass)

			if class != tt.expectedClass {
				t.Errorf("MapAction(%s, %s) class = %s, want %s",
					tt.action, tt.objectClass, class, tt.expectedClass)
			}

			if len(perms) != len(tt.expectedPerms) {
				t.Errorf("MapAction(%s, %s) perms count = %d, want %d",
					tt.action, tt.objectClass, len(perms), len(tt.expectedPerms))
			}
		})
	}
}

func TestActionMapperAddCustomMapping(t *testing.T) {
	am := NewActionMapper()

	am.AddCustomMapping("deploy", "file", []string{"write", "create", "setattr"})

	class, perms := am.MapAction("deploy", "")

	if class != "file" {
		t.Errorf("Custom mapping class = %s, want file", class)
	}

	expectedPerms := []string{"write", "create", "setattr"}
	if len(perms) != len(expectedPerms) {
		t.Errorf("Custom mapping perms count = %d, want %d", len(perms), len(expectedPerms))
	}
}

func TestMapActionWithClass(t *testing.T) {
	am := NewActionMapper()

	tests := []struct {
		name          string
		action        string
		class         string
		expectedPerms []string
	}{
		{
			name:          "Read with file class",
			action:        "read",
			class:         "file",
			expectedPerms: []string{"read", "open", "getattr"},
		},
		{
			name:   "Read with dir class",
			action: "read",
			class:  "dir",
			// Dir adaptation adds extra permissions
			expectedPerms: []string{"read", "search", "open", "getattr"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			perms := am.MapActionWithClass(tt.action, tt.class)

			if len(perms) != len(tt.expectedPerms) {
				t.Errorf("MapActionWithClass(%s, %s) perms count = %d, want %d",
					tt.action, tt.class, len(perms), len(tt.expectedPerms))
			}
		})
	}
}

func TestExpandActionSet(t *testing.T) {
	am := NewActionMapper()

	tests := []struct {
		name      string
		actionSet string
		expected  []string
	}{
		{
			name:      "Read-write shorthand",
			actionSet: "rw",
			expected:  []string{"read", "write"},
		},
		{
			name:      "Read-execute shorthand",
			actionSet: "rx",
			expected:  []string{"read", "execute"},
		},
		{
			name:      "All permissions",
			actionSet: "rwx",
			expected:  []string{"read", "write", "execute"},
		},
		{
			name:      "Comma separated",
			actionSet: "read,write,execute",
			expected:  []string{"read", "write", "execute"},
		},
		{
			name:      "Space separated",
			actionSet: "read write execute",
			expected:  []string{"read", "write", "execute"},
		},
		{
			name:      "Single action",
			actionSet: "read",
			expected:  []string{"read"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := am.ExpandActionSet(tt.actionSet)

			if len(result) != len(tt.expected) {
				t.Errorf("ExpandActionSet(%s) count = %d, want %d",
					tt.actionSet, len(result), len(tt.expected))
				return
			}

			for i, action := range result {
				if action != tt.expected[i] {
					t.Errorf("ExpandActionSet(%s)[%d] = %s, want %s",
						tt.actionSet, i, action, tt.expected[i])
				}
			}
		})
	}
}

func TestGenerateAllowRule(t *testing.T) {
	am := NewActionMapper()

	tests := []struct {
		name       string
		sourceType string
		targetType string
		action     string
		class      string
		expected   string
	}{
		{
			name:       "Simple read rule",
			sourceType: "httpd_t",
			targetType: "httpd_config_t",
			action:     "read",
			class:      "file",
			expected:   "allow httpd_t httpd_config_t:file { read open getattr };",
		},
		{
			name:       "Write rule",
			sourceType: "app_t",
			targetType: "app_log_t",
			action:     "write",
			class:      "file",
			expected:   "allow app_t app_log_t:file { write open append };",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := am.GenerateAllowRule(tt.sourceType, tt.targetType, tt.action, tt.class)
			if result != tt.expected {
				t.Errorf("GenerateAllowRule() = %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestGetSupportedActions(t *testing.T) {
	am := NewActionMapper()

	actions := am.GetSupportedActions()

	if len(actions) == 0 {
		t.Error("Expected supported actions list to be non-empty")
	}

	// Check for some common actions
	expectedActions := []string{"read", "write", "execute", "create", "delete"}
	for _, expected := range expectedActions {
		found := false
		for _, action := range actions {
			if action == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected action '%s' not found in supported actions", expected)
		}
	}
}

func TestGetSupportedClasses(t *testing.T) {
	am := NewActionMapper()

	classes := am.GetSupportedClasses()

	if len(classes) == 0 {
		t.Error("Expected supported classes list to be non-empty")
	}

	// Check for common classes
	expectedClasses := []string{"file", "dir", "tcp_socket", "process"}
	for _, expected := range expectedClasses {
		found := false
		for _, class := range classes {
			if class == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected class '%s' not found in supported classes", expected)
		}
	}
}

func TestLoadCustomMappingsFromConfig(t *testing.T) {
	am := NewActionMapper()

	config := map[string]ActionPermission{
		"backup": {
			Class:       "file",
			Permissions: []string{"read", "write", "create"},
		},
		"restore": {
			Class:       "file",
			Permissions: []string{"write", "create", "unlink"},
		},
	}

	am.LoadCustomMappingsFromConfig(config)

	class, perms := am.MapAction("backup", "")
	if class != "file" {
		t.Errorf("Loaded config mapping class = %s, want file", class)
	}

	if len(perms) != 3 {
		t.Errorf("Loaded config mapping perms count = %d, want 3", len(perms))
	}
}

func TestExportMappings(t *testing.T) {
	am := NewActionMapper()

	am.AddCustomMapping("custom_action", "file", []string{"read", "write"})

	exported := am.ExportMappings()

	if len(exported) == 0 {
		t.Error("Expected exported mappings to be non-empty")
	}

	// Check custom mapping is exported
	if customPerm, exists := exported["custom_action"]; !exists {
		t.Error("Custom mapping not found in exported mappings")
	} else {
		if customPerm.Class != "file" {
			t.Errorf("Exported custom mapping class = %s, want file", customPerm.Class)
		}
	}

	// Check default mapping is also exported
	if _, exists := exported["read"]; !exists {
		t.Error("Default mapping 'read' not found in exported mappings")
	}
}

func TestValidateMapping(t *testing.T) {
	am := NewActionMapper()

	tests := []struct {
		name        string
		action      string
		class       string
		permissions []string
		expectErr   bool
	}{
		{
			name:        "Valid mapping",
			action:      "read",
			class:       "file",
			permissions: []string{"read", "open"},
			expectErr:   false,
		},
		{
			name:        "Empty action",
			action:      "",
			class:       "file",
			permissions: []string{"read"},
			expectErr:   true,
		},
		{
			name:        "Empty class",
			action:      "read",
			class:       "",
			permissions: []string{"read"},
			expectErr:   true,
		},
		{
			name:        "Empty permissions",
			action:      "read",
			class:       "file",
			permissions: []string{},
			expectErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := am.ValidateMapping(tt.action, tt.class, tt.permissions)
			if (err != nil) != tt.expectErr {
				t.Errorf("ValidateMapping() error = %v, expectErr %v", err, tt.expectErr)
			}
		})
	}
}
