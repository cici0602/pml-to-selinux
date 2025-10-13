package models

// SELinuxPolicy represents a complete SELinux policy module
type SELinuxPolicy struct {
	ModuleName   string
	Version      string
	Types        []TypeDeclaration
	Rules        []AllowRule
	DenyRules    []DenyRule
	Transitions  []TypeTransition
	FileContexts []FileContext
}

// TypeDeclaration represents a SELinux type declaration
type TypeDeclaration struct {
	TypeName   string
	Attributes []string // Type attributes if any
}

// AllowRule represents an allow rule in SELinux
type AllowRule struct {
	SourceType  string
	TargetType  string
	Class       string
	Permissions []string
}

// DenyRule represents a deny/neverallow rule in SELinux
type DenyRule struct {
	SourceType  string
	TargetType  string
	Class       string
	Permissions []string
}

// TypeTransition represents a type_transition rule
type TypeTransition struct {
	SourceType string
	TargetType string
	Class      string
	NewType    string
}

// FileContext represents a file context mapping
type FileContext struct {
	PathPattern string // e.g., "/var/www/html(/.*)?"
	FileType    string // e.g., "httpd_var_www_t"
	Context     string // Full context: "system_u:object_r:httpd_var_www_t:s0"
}

// InterfaceDefinition represents a SELinux interface
type InterfaceDefinition struct {
	Name        string
	Description string
	Parameters  []string
	Body        string
}
