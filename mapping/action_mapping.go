package mapping

import (
	"fmt"
	"strings"
)

// ActionMapper handles conversion from PML actions to SELinux permissions
type ActionMapper struct {
	// Custom action mappings (action -> class:permissions)
	customMappings map[string]ActionPermission
	
	// Default action mappings
	defaultMappings map[string]ActionPermission
}

// ActionPermission represents SELinux class and permission set
type ActionPermission struct {
	Class       string   // SELinux object class (e.g., "file", "dir", "tcp_socket")
	Permissions []string // SELinux permissions (e.g., ["read", "open", "getattr"])
}

// NewActionMapper creates a new ActionMapper with default mappings
func NewActionMapper() *ActionMapper {
	am := &ActionMapper{
		customMappings:  make(map[string]ActionPermission),
		defaultMappings: getDefaultActionMappings(),
	}
	return am
}

// getDefaultActionMappings returns default action to permission mappings
func getDefaultActionMappings() map[string]ActionPermission {
	return map[string]ActionPermission{
		// File operations
		"read": {
			Class:       "file",
			Permissions: []string{"read", "open", "getattr"},
		},
		"write": {
			Class:       "file",
			Permissions: []string{"write", "open", "append"},
		},
		"execute": {
			Class:       "file",
			Permissions: []string{"execute", "read", "open", "getattr", "execute_no_trans"},
		},
		"create": {
			Class:       "file",
			Permissions: []string{"create", "write", "open"},
		},
		"delete": {
			Class:       "file",
			Permissions: []string{"unlink"},
		},
		"append": {
			Class:       "file",
			Permissions: []string{"append", "open"},
		},
		"getattr": {
			Class:       "file",
			Permissions: []string{"getattr"},
		},
		"setattr": {
			Class:       "file",
			Permissions: []string{"setattr"},
		},
		"rename": {
			Class:       "file",
			Permissions: []string{"rename"},
		},
		"link": {
			Class:       "file",
			Permissions: []string{"link"},
		},
		"unlink": {
			Class:       "file",
			Permissions: []string{"unlink"},
		},
		
		// Directory operations
		"search": {
			Class:       "dir",
			Permissions: []string{"search", "getattr"},
		},
		"add_name": {
			Class:       "dir",
			Permissions: []string{"add_name", "write"},
		},
		"remove_name": {
			Class:       "dir",
			Permissions: []string{"remove_name", "write"},
		},
		"list": {
			Class:       "dir",
			Permissions: []string{"read", "search", "getattr"},
		},
		"rmdir": {
			Class:       "dir",
			Permissions: []string{"rmdir", "write"},
		},
		
		// Network operations
		"bind": {
			Class:       "tcp_socket",
			Permissions: []string{"bind"},
		},
		"connect": {
			Class:       "tcp_socket",
			Permissions: []string{"connect"},
		},
		"listen": {
			Class:       "tcp_socket",
			Permissions: []string{"listen"},
		},
		"accept": {
			Class:       "tcp_socket",
			Permissions: []string{"accept"},
		},
		"send": {
			Class:       "tcp_socket",
			Permissions: []string{"send"},
		},
		"recv": {
			Class:       "tcp_socket",
			Permissions: []string{"recv"},
		},
		
		// Process operations
		"signal": {
			Class:       "process",
			Permissions: []string{"signal"},
		},
		"sigkill": {
			Class:       "process",
			Permissions: []string{"sigkill"},
		},
		"sigstop": {
			Class:       "process",
			Permissions: []string{"sigstop"},
		},
		"transition": {
			Class:       "process",
			Permissions: []string{"transition"},
		},
		"dyntransition": {
			Class:       "process",
			Permissions: []string{"dyntransition"},
		},
		"getattr_process": {
			Class:       "process",
			Permissions: []string{"getattr"},
		},
		"setattr_process": {
			Class:       "process",
			Permissions: []string{"setattr"},
		},
	}
}

// AddCustomMapping adds a custom action to permission mapping
func (am *ActionMapper) AddCustomMapping(action string, class string, permissions []string) {
	am.customMappings[action] = ActionPermission{
		Class:       class,
		Permissions: permissions,
	}
}

// MapAction maps a PML action to SELinux class and permissions
func (am *ActionMapper) MapAction(action string, objectClass string) (string, []string) {
	actionLower := strings.ToLower(action)
	
	// Check custom mappings first
	if perm, ok := am.customMappings[actionLower]; ok {
		// If object class is provided and different, use it
		if objectClass != "" {
			return objectClass, perm.Permissions
		}
		return perm.Class, perm.Permissions
	}
	
	// Check default mappings
	if perm, ok := am.defaultMappings[actionLower]; ok {
		// If object class is provided and different, use it
		if objectClass != "" {
			// Adapt permissions to the specified class
			return objectClass, am.adaptPermissionsToClass(perm.Permissions, objectClass)
		}
		return perm.Class, perm.Permissions
	}
	
	// If not found, return as-is with provided or default class
	if objectClass == "" {
		objectClass = "file" // default class
	}
	return objectClass, []string{actionLower}
}

// adaptPermissionsToClass adapts permissions to a specific object class
func (am *ActionMapper) adaptPermissionsToClass(permissions []string, class string) []string {
	// If class is dir, adapt file permissions to dir permissions
	if class == "dir" {
		adapted := []string{}
		for _, perm := range permissions {
			switch perm {
			case "read":
				adapted = append(adapted, "read", "search")
			case "write":
				adapted = append(adapted, "write", "add_name", "remove_name")
			case "create":
				adapted = append(adapted, "create", "add_name")
			case "unlink":
				adapted = append(adapted, "remove_name")
			default:
				adapted = append(adapted, perm)
			}
		}
		return removeDuplicatesStrings(adapted)
	}
	
	return permissions
}

// MapActionWithClass maps action to permissions for a specific class
func (am *ActionMapper) MapActionWithClass(action string, class string) []string {
	_, perms := am.MapAction(action, class)
	return perms
}

// GetSupportedActions returns a list of all supported actions
func (am *ActionMapper) GetSupportedActions() []string {
	actions := []string{}
	
	for action := range am.defaultMappings {
		actions = append(actions, action)
	}
	
	for action := range am.customMappings {
		if !containsString(actions, action) {
			actions = append(actions, action)
		}
	}
	
	return actions
}

// GetSupportedClasses returns a list of all supported object classes
func (am *ActionMapper) GetSupportedClasses() []string {
	classes := []string{}
	seen := make(map[string]bool)
	
	for _, perm := range am.defaultMappings {
		if !seen[perm.Class] {
			classes = append(classes, perm.Class)
			seen[perm.Class] = true
		}
	}
	
	for _, perm := range am.customMappings {
		if !seen[perm.Class] {
			classes = append(classes, perm.Class)
			seen[perm.Class] = true
		}
	}
	
	return classes
}

// ExpandActionSet expands compound actions into individual permissions
// For example: "rw" -> ["read", "write"]
func (am *ActionMapper) ExpandActionSet(actionSet string) []string {
	actions := []string{}
	
	// Handle compound actions
	switch strings.ToLower(actionSet) {
	case "rw", "read_write":
		actions = append(actions, "read", "write")
	case "rx", "read_execute":
		actions = append(actions, "read", "execute")
	case "rwx", "all":
		actions = append(actions, "read", "write", "execute")
	default:
		// Split by comma or space
		if strings.Contains(actionSet, ",") {
			actions = strings.Split(actionSet, ",")
		} else if strings.Contains(actionSet, " ") {
			actions = strings.Split(actionSet, " ")
		} else {
			actions = []string{actionSet}
		}
	}
	
	// Trim spaces
	for i, action := range actions {
		actions[i] = strings.TrimSpace(action)
	}
	
	return actions
}

// GenerateAllowRule generates an SELinux allow rule from mapped permissions
func (am *ActionMapper) GenerateAllowRule(sourceType, targetType, action, class string) string {
	seClass, perms := am.MapAction(action, class)
	permsStr := strings.Join(perms, " ")
	return fmt.Sprintf("allow %s %s:%s { %s };", sourceType, targetType, seClass, permsStr)
}

// LoadCustomMappingsFromConfig loads custom mappings from a configuration
func (am *ActionMapper) LoadCustomMappingsFromConfig(config map[string]ActionPermission) {
	for action, perm := range config {
		am.customMappings[action] = perm
	}
}

// ExportMappings exports all mappings for configuration
func (am *ActionMapper) ExportMappings() map[string]ActionPermission {
	exported := make(map[string]ActionPermission)
	
	// Copy default mappings
	for k, v := range am.defaultMappings {
		exported[k] = v
	}
	
	// Override with custom mappings
	for k, v := range am.customMappings {
		exported[k] = v
	}
	
	return exported
}

// ValidateMapping validates if a mapping is valid
func (am *ActionMapper) ValidateMapping(action string, class string, permissions []string) error {
	if action == "" {
		return fmt.Errorf("action cannot be empty")
	}
	
	if class == "" {
		return fmt.Errorf("class cannot be empty")
	}
	
	if len(permissions) == 0 {
		return fmt.Errorf("permissions cannot be empty")
	}
	
	return nil
}

// Helper functions

func removeDuplicatesStrings(slice []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	
	for _, item := range slice {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	
	return result
}

func containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
