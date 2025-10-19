package models

// SELinuxPolicy represents a complete SELinux policy module
// Simplified for 80% use cases: basic domain, file/dir access, ports, sockets
type SELinuxPolicy struct {
	ModuleName   string
	Version      string
	Types        []TypeDeclaration
	Rules        []AllowRule
	Transitions  []TypeTransition
	FileContexts []FileContext
	Interfaces   []InterfaceDefinition
	Capabilities []CapabilityRule
	PortBindings []PortBinding
}

// TypeDeclaration represents a SELinux type declaration
type TypeDeclaration struct {
	TypeName   string
	Attributes []string // Basic attributes: domain, file_type, exec_type, etc.
	Comment    string   // Human-readable description
}

// AllowRule represents an allow rule in SELinux
type AllowRule struct {
	SourceType     string
	TargetType     string
	Class          string   // file, dir, tcp_socket, unix_stream_socket, etc.
	Permissions    []string // read, write, execute, name_bind, etc.
	OriginalObject string   // Original object pattern from PML (for tracking)
	Comment        string   // Human-readable comment
}

// TypeTransition represents a type_transition rule
// Used for automatic labeling when creating files/dirs
type TypeTransition struct {
	SourceType string
	TargetType string
	Class      string
	NewType    string
	Comment    string
}

// FileContext represents a file context mapping
type FileContext struct {
	PathPattern string // e.g., "/var/www/html(/.*)?"
	FileType    string // -- for regular file, -d for directory, etc.
	SELinuxType string // e.g., "httpd_var_www_t"
	Comment     string // Human-readable comment
}

// InterfaceDefinition represents a SELinux interface
// Simplified to provide basic access interfaces for other modules
type InterfaceDefinition struct {
	Name        string
	Description string
	Body        string
}

// CapabilityRule represents a capability grant
// For things like net_bind_service, setuid, etc.
type CapabilityRule struct {
	SourceType string
	Capability string // net_bind_service, setuid, setgid, etc.
	Comment    string
}

// PortBinding represents a port binding suggestion
// Used to generate semanage port commands or port_t declarations
type PortBinding struct {
	Port     int
	Protocol string // tcp, udp
	PortType string // e.g., "http_port_t", "myapp_port_t"
	Comment  string
}

// NewSELinuxPolicy creates a new SELinuxPolicy with default values
func NewSELinuxPolicy(moduleName, version string) *SELinuxPolicy {
	return &SELinuxPolicy{
		ModuleName:   moduleName,
		Version:      version,
		Types:        make([]TypeDeclaration, 0),
		Rules:        make([]AllowRule, 0),
		Transitions:  make([]TypeTransition, 0),
		FileContexts: make([]FileContext, 0),
		Interfaces:   make([]InterfaceDefinition, 0),
		Capabilities: make([]CapabilityRule, 0),
		PortBindings: make([]PortBinding, 0),
	}
}

// AddType adds a type declaration to the policy
func (p *SELinuxPolicy) AddType(typeName string, attributes ...string) {
	p.Types = append(p.Types, TypeDeclaration{
		TypeName:   typeName,
		Attributes: attributes,
	})
}

// AddTypeWithComment adds a type declaration with a comment
func (p *SELinuxPolicy) AddTypeWithComment(typeName, comment string, attributes ...string) {
	p.Types = append(p.Types, TypeDeclaration{
		TypeName:   typeName,
		Attributes: attributes,
		Comment:    comment,
	})
}

// AddAllowRule adds an allow rule to the policy
func (p *SELinuxPolicy) AddAllowRule(rule AllowRule) {
	p.Rules = append(p.Rules, rule)
}

// AddFileContext adds a file context to the policy
func (p *SELinuxPolicy) AddFileContext(fc FileContext) {
	p.FileContexts = append(p.FileContexts, fc)
}

// AddCapability adds a capability rule to the policy
func (p *SELinuxPolicy) AddCapability(cap CapabilityRule) {
	p.Capabilities = append(p.Capabilities, cap)
}

// AddPortBinding adds a port binding suggestion to the policy
func (p *SELinuxPolicy) AddPortBinding(port PortBinding) {
	p.PortBindings = append(p.PortBindings, port)
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

// AddInterface adds an interface definition to the policy
func (p *SELinuxPolicy) AddInterface(iface InterfaceDefinition) {
	p.Interfaces = append(p.Interfaces, iface)
}

// AddTransition adds a type transition to the policy
func (p *SELinuxPolicy) AddTransition(trans TypeTransition) {
	p.Transitions = append(p.Transitions, trans)
}
