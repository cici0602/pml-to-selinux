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

// RoleRelation represents a role/group relationship
type RoleRelation struct {
	Member string // The member of the group
	Role   string // The role/group name
}

// ParsedPML contains all parsed PML data
type ParsedPML struct {
	Model    *PMLModel
	Policies []Policy
	Roles    []RoleRelation
}
