package compiler

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/cici0602/pml-to-selinux/models"
)

// Parser handles parsing of PML model and policy files
type Parser struct {
	modelPath  string
	policyPath string
}

// ParseError represents a parsing error with location information
type ParseError struct {
	File    string
	Line    int
	Message string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("%s:%d: %s", e.File, e.Line, e.Message)
}

// NewParser creates a new parser instance
func NewParser(modelPath, policyPath string) *Parser {
	return &Parser{
		modelPath:  modelPath,
		policyPath: policyPath,
	}
}

// Parse parses both model and policy files and returns ParsedPML in standard Casbin format
func (p *Parser) Parse() (*models.ParsedPML, error) {
	// Parse model file
	model, err := p.parseModel()
	if err != nil {
		return nil, err
	}

	// Parse policy file - now returns standard format
	policies, roles, err := p.parsePolicy()
	if err != nil {
		return nil, err
	}

	return &models.ParsedPML{
		Model:    model,
		Policies: policies,
		Roles:    roles,
	}, nil
}

// Decode decodes standard ParsedPML into SELinux-specific DecodedPML
func (p *Parser) Decode(pml *models.ParsedPML) (*models.DecodedPML, error) {
	decoded := &models.DecodedPML{
		Model:          pml.Model,
		Policies:       make([]models.DecodedPolicy, 0),
		Roles:          make([]models.RoleRelation, 0),
		TypeAttributes: make([]models.RoleRelation, 0),
		Transitions:    make([]models.TransitionInfo, 0),
	}

	// Decode policies
	for _, policy := range pml.Policies {
		decodedPolicy, err := p.decodePolicy(&policy)
		if err != nil {
			return nil, err
		}

		decoded.Policies = append(decoded.Policies, *decodedPolicy)

		// Extract type transitions
		if decodedPolicy.IsTransition && decodedPolicy.TransitionInfo != nil {
			decoded.Transitions = append(decoded.Transitions, *decodedPolicy.TransitionInfo)
		}
	}

	// Decode roles
	for _, role := range pml.Roles {
		if role.Type == "g" {
			// Standard role relation
			decoded.Roles = append(decoded.Roles, role)
		} else if role.Type == "g2" {
			// Type attribute
			decoded.TypeAttributes = append(decoded.TypeAttributes, role)
		}
	}

	return decoded, nil
}

// decodePolicy decodes a standard policy into DecodedPolicy
// Extracts class information from object field or action field, or infers it
func (p *Parser) decodePolicy(policy *models.Policy) (*models.DecodedPolicy, error) {
	decoded := &models.DecodedPolicy{
		Policy: *policy,
	}

	// Extract class from action if explicitly specified (format: "action::class")
	action := policy.Action
	var explicitClass string
	if strings.Contains(action, "::") {
		parts := strings.SplitN(action, "::", 2)
		decoded.Action = parts[0]
		explicitClass = parts[1]
	}

	// Extract class from object if explicitly specified (format: "path::class")
	objPath := policy.Object
	if strings.Contains(objPath, "::") {
		parts := strings.SplitN(objPath, "::", 2)
		decoded.Object = parts[0]
		if explicitClass == "" {
			explicitClass = parts[1]
		}
	}

	// Use explicit class if provided, otherwise infer
	if explicitClass != "" {
		decoded.Class = explicitClass
	} else {
		// Auto-infer class from object and action
		decoded.Class = inferClass(objPath, decoded.Action)
	}

	// Check if object contains a condition (?cond=)
	if strings.Contains(decoded.Object, "?cond=") {
		parts := strings.SplitN(decoded.Object, "?cond=", 2)
		decoded.Object = parts[0]
		decoded.Condition = parts[1]
	}

	// Check if this is a type transition (p2 with action="transition")
	if policy.Type == "p2" && decoded.Action == "transition" {
		decoded.IsTransition = true
		decoded.TransitionInfo = &models.TransitionInfo{
			SourceType: policy.Subject,
			TargetType: decoded.Object,
			Class:      decoded.Class,
			NewType:    policy.Effect,
		}
	}

	return decoded, nil
}

// inferClass infers the SELinux object class from the object path and action
// This implements intelligent defaults for common patterns
func inferClass(object string, action string) string {
	// Special objects
	if object == "self" {
		// Actions on self typically relate to process or capability
		if isCapabilityAction(action) {
			return "capability"
		}
		return "process"
	}

	// Network resources (tcp:port, udp:port format)
	if strings.HasPrefix(object, "tcp:") {
		return "tcp_socket"
	}
	if strings.HasPrefix(object, "udp:") {
		return "udp_socket"
	}

	// Unix socket files (.sock suffix)
	if strings.HasSuffix(object, ".sock") || strings.Contains(object, ".sock") {
		// Check action to determine socket type vs sock_file
		if isSocketAction(action) {
			return "unix_stream_socket"
		}
		return "sock_file"
	}

	// Directory-specific actions
	if isDirectoryAction(action) {
		return "dir"
	}

	// Default to file for file system paths
	if strings.HasPrefix(object, "/") {
		return "file"
	}

	// Fallback
	return "file"
}

// isCapabilityAction checks if action is a capability-related action
func isCapabilityAction(action string) bool {
	capabilityActions := []string{
		"net_bind_service", "setuid", "setgid", "chown", "dac_override",
		"dac_read_search", "fowner", "fsetid", "kill", "sys_admin",
		"sys_chroot", "sys_ptrace", "sys_resource",
	}
	for _, ca := range capabilityActions {
		if action == ca {
			return true
		}
	}
	return false
}

// isSocketAction checks if action is socket-specific (vs file operations on .sock file)
func isSocketAction(action string) bool {
	socketActions := []string{
		"bind", "connect", "listen", "accept", "connectto",
		"sendto", "recvfrom", "send_msg", "recv_msg",
	}
	for _, sa := range socketActions {
		if action == sa {
			return true
		}
	}
	return false
}

// isDirectoryAction checks if action is directory-specific
func isDirectoryAction(action string) bool {
	dirActions := []string{
		"search", "add_name", "remove_name", "reparent", "rmdir",
	}
	for _, da := range dirActions {
		if action == da {
			return true
		}
	}
	return false
}

// parseModel parses the PML model configuration file (.conf)
func (p *Parser) parseModel() (*models.PMLModel, error) {
	file, err := os.Open(p.modelPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open model file: %w", err)
	}
	defer file.Close()

	model := &models.PMLModel{
		RequestDefinition: make(map[string][]string),
		PolicyDefinition:  make(map[string][]string),
		RoleDefinition:    make(map[string][]string),
	}

	scanner := bufio.NewScanner(file)
	lineNum := 0
	currentSection := ""
	hasContent := false

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		hasContent = true

		// Check if this is a section header
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.Trim(line, "[]")
			continue
		}

		// Parse section content
		if currentSection == "" {
			return nil, &ParseError{
				File:    p.modelPath,
				Line:    lineNum,
				Message: "content found outside of section",
			}
		}

		// Split by '=' to get key and value
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return nil, &ParseError{
				File:    p.modelPath,
				Line:    lineNum,
				Message: fmt.Sprintf("invalid line format, expected 'key = value': %s", line),
			}
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch currentSection {
		case "request_definition":
			model.RequestDefinition[key] = parseDefinitionValue(value)
		case "policy_definition":
			model.PolicyDefinition[key] = parseDefinitionValue(value)
		case "role_definition":
			model.RoleDefinition[key] = parseDefinitionValue(value)
		case "policy_effect":
			model.Effect = value
		case "matchers":
			model.Matchers = value
		default:
			return nil, &ParseError{
				File:    p.modelPath,
				Line:    lineNum,
				Message: fmt.Sprintf("unknown section: %s", currentSection),
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading model file: %w", err)
	}

	// Check if the model file was empty
	if !hasContent {
		return nil, &ParseError{
			File:    p.modelPath,
			Line:    0,
			Message: "empty model file",
		}
	}

	return model, nil
}

// parseDefinitionValue parses a definition value like "sub, obj, act, class"
// into a slice of strings
func parseDefinitionValue(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// parsePolicy parses the CSV policy file in standard Casbin format
func (p *Parser) parsePolicy() ([]models.Policy, []models.RoleRelation, error) {
	file, err := os.Open(p.policyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open policy file: %w", err)
	}
	defer file.Close()

	var policies []models.Policy
	var roles []models.RoleRelation

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse CSV line
		fields := parseCSVLine(line)
		if len(fields) == 0 {
			continue
		}

		// Determine the type of rule
		ruleType := fields[0]

		switch ruleType {
		case "p", "p2", "p3":
			// Standard Casbin triple policy rule: p, subject, object, action, effect
			if len(fields) != 5 {
				return nil, nil, &ParseError{
					File:    p.policyPath,
					Line:    lineNum,
					Message: fmt.Sprintf("policy rule expects 5 fields (type, sub, obj, act, eft), got %d: %s", len(fields), line),
				}
			}
			// Validate effect field
			effect := strings.TrimSpace(fields[4])
			if effect != "allow" && effect != "deny" {
				return nil, nil, &ParseError{
					File:    p.policyPath,
					Line:    lineNum,
					Message: fmt.Sprintf("invalid effect '%s', must be 'allow' or 'deny'", effect),
				}
			}

			policies = append(policies, models.Policy{
				Type:    ruleType,
				Subject: strings.TrimSpace(fields[1]),
				Object:  strings.TrimSpace(fields[2]),
				Action:  strings.TrimSpace(fields[3]),
				Effect:  effect,
			})

		case "g", "g2", "g3":
			// Standard role relation: g, member, role
			if len(fields) != 3 {
				return nil, nil, &ParseError{
					File:    p.policyPath,
					Line:    lineNum,
					Message: fmt.Sprintf("role relation expects 3 fields, got %d: %s", len(fields), line),
				}
			}
			roles = append(roles, models.RoleRelation{
				Type:   ruleType,
				Member: strings.TrimSpace(fields[1]),
				Role:   strings.TrimSpace(fields[2]),
			})

		default:
			return nil, nil, &ParseError{
				File:    p.policyPath,
				Line:    lineNum,
				Message: fmt.Sprintf("unknown rule type: %s (only p, p2, p3, g, g2, g3 are supported)", ruleType),
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("error reading policy file: %w", err)
	}

	return policies, roles, nil
}

// parseCSVLine parses a CSV line, handling simple quoted fields
func parseCSVLine(line string) []string {
	var fields []string
	var current strings.Builder
	inQuotes := false

	for i := 0; i < len(line); i++ {
		c := line[i]

		switch c {
		case '"':
			inQuotes = !inQuotes
		case ',':
			if inQuotes {
				current.WriteByte(c)
			} else {
				fields = append(fields, current.String())
				current.Reset()
			}
		default:
			current.WriteByte(c)
		}
	}

	// Add the last field
	fields = append(fields, current.String())

	// Trim whitespace from all fields
	for i := range fields {
		fields[i] = strings.TrimSpace(fields[i])
	}

	return fields
}
