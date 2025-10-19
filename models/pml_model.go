package models

// PMLModel represents a Casbin PML model structure
type PMLModel struct {
	RequestDefinition map[string][]string // r = sub, obj, act, class
	PolicyDefinition  map[string][]string // p = sub, obj, act, class, eft; p2 = sub, obj, act, class, eft
	RoleDefinition    map[string][]string // g = _, _; g2 = _, _
	Matchers          string              // Matching rules
	Effect            string              // Policy effect
}

// Policy represents a single policy rule from PML
// This is the standard Casbin policy format, fully compatible
type Policy struct {
	Type    string // "p", "p2", etc. - policy definition type
	Subject string // e.g., "httpd_t"
	Object  string // e.g., "/var/www/*" or "/home/*?cond=httpd_enable_homedirs"
	Action  string // e.g., "read", "write", "transition"
	Class   string // e.g., "file", "dir", "process"
	Effect  string // "allow" or "deny" (for p) or new_type (for p2 transitions)
}

// RoleRelation represents a role/group relationship
// This is used for both standard roles (g) and extended attributes (g2)
type RoleRelation struct {
	Type   string // "g", "g2", "g3", etc.
	Member string // The member of the group or attribute name
	Role   string // The role/group name or encoded value (e.g., "bool:true")
}

// DecodedPolicy contains decoded policy information
// This is internal representation after decoding standard PML
type DecodedPolicy struct {
	Policy                         // Embedded standard policy
	Condition      string          // Extracted condition (from ?cond= in object)
	IsTransition   bool            // True if this is a type transition (p2 with action="transition")
	TransitionInfo *TransitionInfo // Details for type transitions
}

// TransitionInfo contains type transition details
type TransitionInfo struct {
	SourceType string // Domain that creates the object
	TargetType string // Type of the parent object (from Object field)
	Class      string // Object class (from Class field)
	NewType    string // Resulting type (from Effect field for p2)
}

// ParsedPML contains all parsed PML data in standard Casbin format
type ParsedPML struct {
	Model    *PMLModel
	Policies []Policy       // All policies (p, p2, etc.)
	Roles    []RoleRelation // All role relations (g, g2, etc.)
}

// DecodedPML contains decoded PML data with SELinux-specific structures
// This is created by decoding the standard ParsedPML
type DecodedPML struct {
	Model          *PMLModel
	Policies       []DecodedPolicy  // Decoded policies
	Roles          []RoleRelation   // Standard role relations (g)
	TypeAttributes []RoleRelation   // Type attributes (g2)
	Transitions    []TransitionInfo // Extracted type transitions (from p2)
}
