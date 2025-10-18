package mapping

import (
	"testing"
)

// TestActionMapper_Phase1Requirements tests all Phase 1 required mappings
func TestActionMapper_Phase1Requirements(t *testing.T) {
	mapper := NewActionMapper()

	// Test basic file operations (Phase 1 requirement)
	fileActions := []struct {
		action        string
		expectedClass string
		requiredPerms []string
	}{
		{"read", "file", []string{"read", "open", "getattr"}},
		{"write", "file", []string{"write", "open", "append"}},
		{"execute", "file", []string{"execute", "read", "open", "getattr", "execute_no_trans"}},
		{"create", "file", []string{"create", "write", "open"}},
		{"delete", "file", []string{"unlink"}},
	}

	for _, test := range fileActions {
		t.Run("file_"+test.action, func(t *testing.T) {
			class, perms := mapper.MapAction(test.action, "")

			if class != test.expectedClass {
				t.Errorf("Expected class %s, got %s", test.expectedClass, class)
			}

			// Check that all required permissions are present
			for _, reqPerm := range test.requiredPerms {
				found := false
				for _, perm := range perms {
					if perm == reqPerm {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Required permission %s not found in %v for action %s", reqPerm, perms, test.action)
				}
			}
		})
	}

	// Test directory operations
	dirActions := []struct {
		action        string
		expectedClass string
		requiredPerms []string
	}{
		{"search", "dir", []string{"search", "getattr"}},
		{"list", "dir", []string{"read", "search", "getattr"}},
		{"add_name", "dir", []string{"add_name", "write"}},
		{"remove_name", "dir", []string{"remove_name", "write"}},
	}

	for _, test := range dirActions {
		t.Run("dir_"+test.action, func(t *testing.T) {
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
					t.Errorf("Required permission %s not found in %v for action %s", reqPerm, perms, test.action)
				}
			}
		})
	}

	// Test basic network operations (Phase 1 requirement)
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
					t.Errorf("Required permission %s not found in %v for action %s", reqPerm, perms, test.action)
				}
			}
		})
	}

	// Test basic process operations (Phase 1 requirement)
	processActions := []struct {
		action        string
		expectedClass string
		requiredPerms []string
	}{
		{"transition", "process", []string{"transition"}},
		{"signal", "process", []string{"signal"}},
		{"getattr_process", "process", []string{"getattr"}},
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
					t.Errorf("Required permission %s not found in %v for action %s", reqPerm, perms, test.action)
				}
			}
		})
	}
}

// TestActionMapper_ClassAdaptation tests class adaptation functionality
func TestActionMapper_ClassAdaptation(t *testing.T) {
	mapper := NewActionMapper()

	// Test that read action works with different object classes
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
	mapper := NewActionMapper()

	// Add custom mapping
	mapper.AddCustomMapping("custom_read", "special_file", []string{"custom_read", "custom_open"})

	class, perms := mapper.MapAction("custom_read", "")

	expectedClass := "special_file"
	expectedPerms := []string{"custom_read", "custom_open"}

	if class != expectedClass {
		t.Errorf("Expected class %s, got %s", expectedClass, class)
	}

	if len(perms) != len(expectedPerms) {
		t.Errorf("Expected %d permissions, got %d", len(expectedPerms), len(perms))
	}

	for i, expectedPerm := range expectedPerms {
		if i >= len(perms) || perms[i] != expectedPerm {
			t.Errorf("Expected permission %s at index %d, got %v", expectedPerm, i, perms)
		}
	}
}
