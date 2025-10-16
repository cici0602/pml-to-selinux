package models

// PMLModel represents a Casbin PML model structure
type PMLModel struct {
	RequestDefinition map[string][]string // r = sub, obj, act, class
	PolicyDefinition  map[string][]string // p = sub, obj, act, class, eft
	RoleDefinition    map[string][]string // g = _, _
	Matchers          string              // Matching rules
	Effect            string              // Policy effect
}

// Policy represents a single policy rule from PML
type Policy struct {
	Subject string // e.g., "httpd_t"
	Object  string // e.g., "/var/www/*"
	Action  string // e.g., "read"
	Class   string // e.g., "file"
	Effect  string // "allow" or "deny"
}

// Transition represents a type transition rule from PML
// Format: t, source_type, target_type, class, new_type
type Transition struct {
	SourceType string // Domain that creates the object
	TargetType string // Type of the parent object
	Class      string // Object class (file, dir, etc.)
	NewType    string // Resulting type of the new object
}

// RoleRelation represents a role/group relationship
type RoleRelation struct {
	Member string // The member of the group
	Role   string // The role/group name
}

// BooleanDefinition represents a SELinux boolean definition
// Format: bool, name, default_value, description
type BooleanDefinition struct {
	Name         string // e.g., "httpd_can_network_connect"
	DefaultValue bool   // true or false
	Description  string // Human-readable description
}

// ParsedPML contains all parsed PML data
type ParsedPML struct {
	Model       *PMLModel
	Policies    []Policy
	Roles       []RoleRelation
	Transitions []Transition
	Booleans    []BooleanDefinition
}
