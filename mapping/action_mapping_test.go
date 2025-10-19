package mapping

import (
	"testing"
)

// TestActionMapper_BasicMappings tests basic action to permission mappings
func TestActionMapper_BasicMappings(t *testing.T) {
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
			name:          "Create file",
			action:        "create",
			objectClass:   "",
			expectedClass: "file",
			expectedPerms: []string{"create", "write", "open"},
		},
		{
			name:          "Delete file",
			action:        "delete",
			objectClass:   "",
			expectedClass: "file",
			expectedPerms: []string{"unlink"},
		},
		{
			name:          "Append to file",
			action:        "append",
			objectClass:   "",
			expectedClass: "file",
			expectedPerms: []string{"append", "open"},
		},
		{
			name:          "Search directory",
			action:        "search",
			objectClass:   "",
			expectedClass: "dir",
			expectedPerms: []string{"search", "getattr"},
		},
		{
			name:          "List directory",
			action:        "list",
			objectClass:   "",
			expectedClass: "dir",
			expectedPerms: []string{"read", "search", "getattr"},
		},
		{
			name:          "Add name to directory",
			action:        "add_name",
			objectClass:   "",
			expectedClass: "dir",
			expectedPerms: []string{"add_name", "write"},
		},
		{
			name:          "Remove name from directory",
			action:        "remove_name",
			objectClass:   "",
			expectedClass: "dir",
			expectedPerms: []string{"remove_name", "write"},
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
				t.Errorf("MapAction(%s, %s) perms count = %d, want %d. Got: %v, Want: %v",
					tt.action, tt.objectClass, len(perms), len(tt.expectedPerms), perms, tt.expectedPerms)
			}

			// Check that all expected permissions are present
			for _, expectedPerm := range tt.expectedPerms {
				found := false
				for _, perm := range perms {
					if perm == expectedPerm {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected permission %s not found in %v for action %s",
						expectedPerm, perms, tt.action)
				}
			}
		})
	}
}

// TestActionMapper_NetworkOperations tests network-related action mappings
func TestActionMapper_NetworkOperations(t *testing.T) {
	mapper := NewActionMapper()

	networkActions := []struct {
		action        string
		expectedClass string
		requiredPerms []string
	}{
		{"bind", "tcp_socket", []string{"bind"}},
		{"connect", "tcp_socket", []string{"connect"}},
		{"listen", "tcp_socket", []string{"listen"}},
		{"accept", "tcp_socket", []string{"accept"}},
		{"send", "tcp_socket", []string{"send"}},
		{"recv", "tcp_socket", []string{"recv"}},
	}

	for _, test := range networkActions {
		t.Run("network_"+test.action, func(t *testing.T) {
			class, perms := mapper.MapAction(test.action, "")

			if class != test.expectedClass {
				t.Errorf("Expected class %s, got %s", test.expectedClass, class)
			}

			for _, reqPerm := range test.requiredPerms {
				found := false
				for _, perm := range perms {
					if perm == reqPerm {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Required permission %s not found in %v for action %s",
						reqPerm, perms, test.action)
				}
			}
		})
	}
}

// TestActionMapper_ProcessOperations tests process-related action mappings
func TestActionMapper_ProcessOperations(t *testing.T) {
	mapper := NewActionMapper()

	processActions := []struct {
		action        string
		expectedClass string
		requiredPerms []string
	}{
		{"transition", "process", []string{"transition"}},
		{"signal", "process", []string{"signal"}},
		{"getattr_process", "process", []string{"getattr"}},
		{"sigkill", "process", []string{"sigkill"}},
		{"sigstop", "process", []string{"sigstop"}},
	}

	for _, test := range processActions {
		t.Run("process_"+test.action, func(t *testing.T) {
			class, perms := mapper.MapAction(test.action, "")

			if class != test.expectedClass {
				t.Errorf("Expected class %s, got %s", test.expectedClass, class)
			}

			for _, reqPerm := range test.requiredPerms {
				found := false
				for _, perm := range perms {
					if perm == reqPerm {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Required permission %s not found in %v for action %s",
						reqPerm, perms, test.action)
				}
			}
		})
	}
}

// TestActionMapper_ClassAdaptation tests class adaptation functionality
func TestActionMapper_ClassAdaptation(t *testing.T) {
	mapper := NewActionMapper()

	testCases := []struct {
		action        string
		objectClass   string
		expectedClass string
	}{
		{"read", "", "file"},                                    // Default to file
		{"read", "dir", "dir"},                                  // Adapt to dir
		{"read", "lnk_file", "lnk_file"},                        // Adapt to link file
		{"connect", "", "tcp_socket"},                           // Default to tcp_socket
		{"connect", "unix_stream_socket", "unix_stream_socket"}, // Adapt to unix socket
	}

	for _, test := range testCases {
		t.Run(test.action+"_"+test.objectClass, func(t *testing.T) {
			class, _ := mapper.MapAction(test.action, test.objectClass)

			if class != test.expectedClass {
				t.Errorf("Expected class %s, got %s for action %s with object class %s",
					test.expectedClass, class, test.action, test.objectClass)
			}
		})
	}
}

// TestActionMapper_UnknownActions tests handling of unknown actions
func TestActionMapper_UnknownActions(t *testing.T) {
	mapper := NewActionMapper()

	unknownActions := []string{"unknown_action", "custom_operation", "special_task"}

	for _, action := range unknownActions {
		t.Run("unknown_"+action, func(t *testing.T) {
			class, perms := mapper.MapAction(action, "")

			// Should default to file class
			if class != "file" {
				t.Errorf("Expected default class 'file', got %s", class)
			}

			// Should return action as permission
			if len(perms) != 1 || perms[0] != action {
				t.Errorf("Expected [%s], got %v", action, perms)
			}
		})
	}
}

// TestActionMapper_CustomMappings tests custom mapping functionality
func TestActionMapper_CustomMappings(t *testing.T) {
	am := NewActionMapper()

	// Add custom mapping
	am.AddCustomMapping("deploy", "file", []string{"write", "create", "setattr"})

	class, perms := am.MapAction("deploy", "")

	if class != "file" {
		t.Errorf("Custom mapping class = %s, want file", class)
	}

	expectedPerms := []string{"write", "create", "setattr"}
	if len(perms) != len(expectedPerms) {
		t.Errorf("Custom mapping perms count = %d, want %d", len(perms), len(expectedPerms))
	}

	for i, expectedPerm := range expectedPerms {
		if i >= len(perms) || perms[i] != expectedPerm {
			t.Errorf("Expected permission %s at index %d, got %v", expectedPerm, i, perms)
		}
	}
}

// TestMapActionWithClass tests action mapping with specific class
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
				t.Errorf("MapActionWithClass(%s, %s) perms count = %d, want %d. Got: %v, Want: %v",
					tt.action, tt.class, len(perms), len(tt.expectedPerms), perms, tt.expectedPerms)
			}
		})
	}
}

// TestExpandActionSet tests action set expansion
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

// TestGenerateAllowRule tests SELinux allow rule generation
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

// TestGetSupportedActions tests getting list of supported actions
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

// TestGetSupportedClasses tests getting list of supported classes
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

// TestLoadCustomMappingsFromConfig tests loading custom mappings from config
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

// TestExportMappings tests exporting all mappings
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

// TestValidateMapping tests mapping validation
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
