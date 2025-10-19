package selinux

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cici0602/pml-to-selinux/mapping"
)

// FSGenerator handles generation of filesystem context rules
type FSGenerator struct {
	fsMapper      *mapping.FilesystemMapper
	genfsconRules []mapping.GenfsconRule
	fsuseRules    []mapping.FsuseRule
	portconRules  []mapping.PortconRule
	netifconRules []mapping.NetifconRule
}

// NewFSGenerator creates a new FSGenerator
func NewFSGenerator(fsMapper *mapping.FilesystemMapper) *FSGenerator {
	return &FSGenerator{
		fsMapper:      fsMapper,
		genfsconRules: make([]mapping.GenfsconRule, 0),
		fsuseRules:    make([]mapping.FsuseRule, 0),
		portconRules:  make([]mapping.PortconRule, 0),
		netifconRules: make([]mapping.NetifconRule, 0),
	}
}

// AddGenfsconRule adds a genfscon rule
func (g *FSGenerator) AddGenfsconRule(rule mapping.GenfsconRule) {
	g.genfsconRules = append(g.genfsconRules, rule)
}

// AddFsuseRule adds a fsuse rule
func (g *FSGenerator) AddFsuseRule(rule mapping.FsuseRule) {
	g.fsuseRules = append(g.fsuseRules, rule)
}

// AddPortconRule adds a portcon rule
func (g *FSGenerator) AddPortconRule(rule mapping.PortconRule) {
	g.portconRules = append(g.portconRules, rule)
}

// AddNetifconRule adds a netifcon rule
func (g *FSGenerator) AddNetifconRule(rule mapping.NetifconRule) {
	g.netifconRules = append(g.netifconRules, rule)
}

// Generate generates all filesystem context statements
func (g *FSGenerator) Generate() (string, error) {
	var builder strings.Builder

	// Validate rules first
	if errors := g.fsMapper.ValidateFilesystemPolicy(g.genfsconRules, g.fsuseRules); len(errors) > 0 {
		return "", fmt.Errorf("validation failed: %v", errors)
	}

	// Generate genfscon rules
	if len(g.genfsconRules) > 0 {
		builder.WriteString("########################################\n")
		builder.WriteString("# Generic Filesystem Context Rules\n")
		builder.WriteString("########################################\n\n")
		g.writeGenfsconRules(&builder)
		builder.WriteString("\n")
	}

	// Generate fsuse rules
	if len(g.fsuseRules) > 0 {
		builder.WriteString("########################################\n")
		builder.WriteString("# Filesystem Use Rules\n")
		builder.WriteString("########################################\n\n")
		g.writeFsuseRules(&builder)
		builder.WriteString("\n")
	}

	// Generate portcon rules
	if len(g.portconRules) > 0 {
		builder.WriteString("########################################\n")
		builder.WriteString("# Port Context Rules\n")
		builder.WriteString("########################################\n\n")
		g.writePortconRules(&builder)
		builder.WriteString("\n")
	}

	// Generate netifcon rules
	if len(g.netifconRules) > 0 {
		builder.WriteString("########################################\n")
		builder.WriteString("# Network Interface Context Rules\n")
		builder.WriteString("########################################\n\n")
		g.writeNetifconRules(&builder)
		builder.WriteString("\n")
	}

	return builder.String(), nil
}

// writeGenfsconRules writes genfscon rules
func (g *FSGenerator) writeGenfsconRules(builder *strings.Builder) {
	// Group rules by filesystem type
	rulesByFS := make(map[string][]mapping.GenfsconRule)
	for _, rule := range g.genfsconRules {
		rulesByFS[rule.FSType] = append(rulesByFS[rule.FSType], rule)
	}

	// Sort filesystem types
	fsTypes := make([]string, 0, len(rulesByFS))
	for fsType := range rulesByFS {
		fsTypes = append(fsTypes, fsType)
	}
	sort.Strings(fsTypes)

	// Write rules grouped by filesystem
	for _, fsType := range fsTypes {
		rules := rulesByFS[fsType]

		// Sort rules by path
		sort.Slice(rules, func(i, j int) bool {
			return rules[i].Path < rules[j].Path
		})

		builder.WriteString(fmt.Sprintf("# %s filesystem\n", fsType))
		for _, rule := range rules {
			builder.WriteString(fmt.Sprintf("genfscon %s %s %s\n", rule.FSType, rule.Path, rule.Context))
		}
		builder.WriteString("\n")
	}
}

// writeFsuseRules writes fsuse rules
func (g *FSGenerator) writeFsuseRules(builder *strings.Builder) {
	// Group rules by use type
	rulesByType := make(map[string][]mapping.FsuseRule)
	for _, rule := range g.fsuseRules {
		rulesByType[rule.UseType] = append(rulesByType[rule.UseType], rule)
	}

	// Write in order: xattr, trans, task
	useTypes := []string{"xattr", "trans", "task"}

	for _, useType := range useTypes {
		rules, ok := rulesByType[useType]
		if !ok || len(rules) == 0 {
			continue
		}

		// Sort rules by filesystem type
		sort.Slice(rules, func(i, j int) bool {
			return rules[i].FSType < rules[j].FSType
		})

		builder.WriteString(fmt.Sprintf("# Filesystems using %s\n", useType))
		for _, rule := range rules {
			builder.WriteString(fmt.Sprintf("fs_use_%s %s %s;\n", rule.UseType, rule.FSType, rule.Context))
		}
		builder.WriteString("\n")
	}
}

// writePortconRules writes portcon rules
func (g *FSGenerator) writePortconRules(builder *strings.Builder) {
	// Group rules by protocol
	rulesByProto := make(map[string][]mapping.PortconRule)
	for _, rule := range g.portconRules {
		rulesByProto[rule.Protocol] = append(rulesByProto[rule.Protocol], rule)
	}

	// Write TCP rules first, then UDP
	protocols := []string{"tcp", "udp"}

	for _, protocol := range protocols {
		rules, ok := rulesByProto[protocol]
		if !ok || len(rules) == 0 {
			continue
		}

		// Sort rules by port number
		sort.Slice(rules, func(i, j int) bool {
			return rules[i].Port < rules[j].Port
		})

		builder.WriteString(fmt.Sprintf("# %s ports\n", strings.ToUpper(protocol)))
		for _, rule := range rules {
			if rule.PortEnd > 0 && rule.PortEnd != rule.Port {
				// Port range
				builder.WriteString(fmt.Sprintf("portcon %s %d-%d %s\n", rule.Protocol, rule.Port, rule.PortEnd, rule.Context))
			} else {
				// Single port
				builder.WriteString(fmt.Sprintf("portcon %s %d %s\n", rule.Protocol, rule.Port, rule.Context))
			}
		}
		builder.WriteString("\n")
	}
}

// writeNetifconRules writes netifcon rules
func (g *FSGenerator) writeNetifconRules(builder *strings.Builder) {
	// Sort rules by interface name
	sort.Slice(g.netifconRules, func(i, j int) bool {
		return g.netifconRules[i].Interface < g.netifconRules[j].Interface
	})

	for _, rule := range g.netifconRules {
		builder.WriteString(fmt.Sprintf("netifcon %s %s %s\n", rule.Interface, rule.IfContext, rule.PacketContext))
	}
}

// GenerateDefaultRules generates default filesystem context rules
func (g *FSGenerator) GenerateDefaultRules() {
	// Add default genfscon rules
	for _, rule := range g.fsMapper.GenerateGenfsconRules() {
		g.AddGenfsconRule(rule)
	}

	// Add default fsuse rules
	for _, rule := range g.fsMapper.GenerateFsuseRules() {
		g.AddFsuseRule(rule)
	}

	// Add default portcon rules
	for _, rule := range g.fsMapper.GeneratePortconRules() {
		g.AddPortconRule(rule)
	}
}

// GenerateRelabelScript generates a relabeling script for filesystems
func (g *FSGenerator) GenerateRelabelScript() string {
	var builder strings.Builder

	builder.WriteString("#!/bin/bash\n")
	builder.WriteString("# SELinux Filesystem Relabeling Script\n")
	builder.WriteString("# Generated by PML-to-SELinux Compiler\n\n")

	builder.WriteString("set -e\n\n")

	builder.WriteString("echo \"Starting filesystem relabeling...\"\n\n")

	// Generate restorecon commands
	builder.WriteString("# Restore file contexts\n")
	builder.WriteString("if command -v restorecon >/dev/null 2>&1; then\n")
	builder.WriteString("    echo \"Using restorecon...\"\n")
	builder.WriteString("    restorecon -R -v /\n")
	builder.WriteString("else\n")
	builder.WriteString("    echo \"restorecon not found, using setfiles...\"\n")
	builder.WriteString("    if [ -f /etc/selinux/targeted/contexts/files/file_contexts ]; then\n")
	builder.WriteString("        setfiles -r / /etc/selinux/targeted/contexts/files/file_contexts /\n")
	builder.WriteString("    fi\n")
	builder.WriteString("fi\n\n")

	// Add specific relabeling for pseudo-filesystems
	builder.WriteString("# Relabel pseudo-filesystems\n")
	for _, rule := range g.genfsconRules {
		if rule.FSType == "proc" || rule.FSType == "sysfs" {
			builder.WriteString(fmt.Sprintf("# %s %s\n", rule.FSType, rule.Path))
		}
	}
	builder.WriteString("\n")

	builder.WriteString("echo \"Filesystem relabeling completed.\"\n")

	return builder.String()
}

// Validate validates all filesystem rules
func (g *FSGenerator) Validate() error {
	errors := g.fsMapper.ValidateFilesystemPolicy(g.genfsconRules, g.fsuseRules)
	if len(errors) > 0 {
		return fmt.Errorf("validation failed: %v", errors)
	}
	return nil
}
