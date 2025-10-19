package models

// PMLModel represents a Casbin PML model structure
// Now using standard Casbin triple format: (sub, obj, act)
type PMLModel struct {
	RequestDefinition map[string][]string // r = sub, obj, act
	PolicyDefinition  map[string][]string // p = sub, obj, act, eft; p2 = sub, obj, act, eft
	RoleDefinition    map[string][]string // g = _, _; g2 = _, _
	Matchers          string              // Matching rules
	Effect            string              // Policy effect
}

// Policy represents a single policy rule from PML
// This is the standard Casbin triple format (sub, obj, act) with optional effect
// Class information is encoded in the Object field using format:
//   - Explicit: "/var/log/myapp::file" or "tcp:8080::tcp_socket"
//   - Auto-inferred from path patterns (paths → file/dir, tcp:/udp: → socket)
type Policy struct {
	Type    string // "p", "p2", etc. - policy definition type
	Subject string // e.g., "myapp_t" - SELinux domain/type
	Object  string // e.g., "/var/www/*" or "/var/log/app.log::file" or "tcp:8080::tcp_socket"
	Action  string // e.g., "read", "write", "execute", "bind", "transition"
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
// This is internal representation after decoding standard PML triple format
// The Class field is extracted from Object field (e.g., "/path::file" → Class="file")
type DecodedPolicy struct {
	Policy                         // Embedded standard policy
	Class          string          // Extracted or inferred SELinux object class (file, dir, tcp_socket, etc.)
	Condition      string          // Extracted condition (from ?cond= in object)
	IsTransition   bool            // True if this is a type transition (p2 with action="transition")
	TransitionInfo *TransitionInfo // Details for type transitions
}

// TransitionInfo contains type transition details
type TransitionInfo struct {
	SourceType string // Domain that creates the object
	TargetType string // Type of the parent object (from Object field)
	Class      string // Object class (extracted from Object or inferred)
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
