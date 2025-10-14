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
	SourceType     string
	TargetType     string
	Class          string
	Permissions    []string
	OriginalObject string // Original object pattern from PML (for tracking)
}

// DenyRule represents a deny/neverallow rule in SELinux
type DenyRule struct {
	SourceType     string
	TargetType     string
	Class          string
	Permissions    []string
	OriginalObject string // Original object pattern from PML
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
	User        string // SELinux user (default: "system_u")
	Role        string // SELinux role (default: "object_r")
	Level       string // MLS/MCS level (default: "s0")
}

// InterfaceDefinition represents a SELinux interface
type InterfaceDefinition struct {
	Name        string
	Description string
	Parameters  []string
	Body        string
}

// NewSELinuxPolicy creates a new SELinuxPolicy with default values
func NewSELinuxPolicy(moduleName, version string) *SELinuxPolicy {
	return &SELinuxPolicy{
		ModuleName:   moduleName,
		Version:      version,
		Types:        make([]TypeDeclaration, 0),
		Rules:        make([]AllowRule, 0),
		DenyRules:    make([]DenyRule, 0),
		Transitions:  make([]TypeTransition, 0),
		FileContexts: make([]FileContext, 0),
	}
}

// AddType adds a type declaration to the policy
func (p *SELinuxPolicy) AddType(typeName string, attributes ...string) {
	p.Types = append(p.Types, TypeDeclaration{
		TypeName:   typeName,
		Attributes: attributes,
	})
}

// AddAllowRule adds an allow rule to the policy
func (p *SELinuxPolicy) AddAllowRule(rule AllowRule) {
	p.Rules = append(p.Rules, rule)
}

// AddDenyRule adds a deny rule to the policy
func (p *SELinuxPolicy) AddDenyRule(rule DenyRule) {
	p.DenyRules = append(p.DenyRules, rule)
}

// AddFileContext adds a file context to the policy with defaults
func (p *SELinuxPolicy) AddFileContext(fc FileContext) {
	// Set defaults if not provided
	if fc.User == "" {
		fc.User = "system_u"
	}
	if fc.Role == "" {
		fc.Role = "object_r"
	}
	if fc.Level == "" {
		fc.Level = "s0"
	}
	// Build full context string
	if fc.Context == "" {
		fc.Context = fc.User + ":" + fc.Role + ":" + fc.FileType + ":" + fc.Level
	}
	p.FileContexts = append(p.FileContexts, fc)
}

// GetTypeByName returns a type declaration by name
func (p *SELinuxPolicy) GetTypeByName(name string) *TypeDeclaration {
	for i := range p.Types {
		if p.Types[i].TypeName == name {
			return &p.Types[i]
		}
	}
	return nil
}

// HasType checks if a type exists in the policy
func (p *SELinuxPolicy) HasType(typeName string) bool {
	return p.GetTypeByName(typeName) != nil
}
