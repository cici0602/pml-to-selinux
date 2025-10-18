package mapping

import (
	"fmt"
	"strings"

	"github.com/cici0602/pml-to-selinux/models"
)

// AutoTransitionMapper handles automatic domain transition rules
type AutoTransitionMapper struct {
	typeMapper   *TypeMapper
	actionMapper *ActionMapper
}

// NewAutoTransitionMapper creates a new AutoTransitionMapper
func NewAutoTransitionMapper(typeMapper *TypeMapper, actionMapper *ActionMapper) *AutoTransitionMapper {
	return &AutoTransitionMapper{
		typeMapper:   typeMapper,
		actionMapper: actionMapper,
	}
}

// AutoTransitionRule represents an automatically inferred domain transition
type AutoTransitionRule struct {
	SourceDomain string   // Source domain (caller)
	TargetDomain string   // Target domain (new process)
	EntryPoint   string   // Entry point executable type
	AutoInferred bool     // Whether this was automatically inferred
	Conditions   []string // Additional conditions for transition
}

// TransitionPath represents a chain of domain transitions
type TransitionPath struct {
	Domains []string // Sequence of domains in the transition path
	Valid   bool     // Whether the path is valid
	Reason  string   // Reason if invalid
}

// InferAutoTransitions infers automatic domain transitions from type transitions
func (atm *AutoTransitionMapper) InferAutoTransitions(
	typeTransitions []models.TypeTransition,
	allowRules []models.AllowRule,
) []AutoTransitionRule {
	autoRules := make([]AutoTransitionRule, 0)

	// Build a map of existing allow rules for quick lookup
	allowMap := make(map[string]map[string]bool)
	for _, rule := range allowRules {
		if allowMap[rule.SourceType] == nil {
			allowMap[rule.SourceType] = make(map[string]bool)
		}
		allowMap[rule.SourceType][rule.TargetType] = true
	}

	for _, trans := range typeTransitions {
		// Only process process transitions
		if trans.Class != "process" {
			continue
		}

		// Check if this is a candidate for auto transition
		if atm.isAutoTransitionCandidate(trans, allowMap) {
			autoRule := AutoTransitionRule{
				SourceDomain: trans.SourceType,
				TargetDomain: trans.NewType,
				EntryPoint:   trans.TargetType,
				AutoInferred: true,
				Conditions:   atm.inferTransitionConditions(trans),
			}
			autoRules = append(autoRules, autoRule)
		}
	}

	return autoRules
}

// isAutoTransitionCandidate checks if a type transition is suitable for auto transition
func (atm *AutoTransitionMapper) isAutoTransitionCandidate(
	trans models.TypeTransition,
	allowMap map[string]map[string]bool,
) bool {
	// Check if source domain has execute permission on entry point
	if allowMap[trans.SourceType] == nil {
		return false
	}

	// Entry point should be executable
	if !atm.isExecutableType(trans.TargetType) {
		return false
	}

	// Target domain should be different from source
	if trans.SourceType == trans.NewType {
		return false
	}

	return true
}

// isExecutableType checks if a type is an executable file type
func (atm *AutoTransitionMapper) isExecutableType(typeName string) bool {
	// Check for common executable type suffixes
	execSuffixes := []string{
		"_exec_t",
		"_bin_t",
		"_cmd_t",
		"_program_t",
	}

	for _, suffix := range execSuffixes {
		if strings.HasSuffix(typeName, suffix) {
			return true
		}
	}

	return false
}

// inferTransitionConditions infers conditions required for a transition
func (atm *AutoTransitionMapper) inferTransitionConditions(trans models.TypeTransition) []string {
	conditions := []string{}

	// Entry point condition
	conditions = append(conditions, fmt.Sprintf("type=%s", trans.TargetType))

	// Additional conditions based on source/target domains
	if atm.isPrivilegedDomain(trans.NewType) {
		conditions = append(conditions, "privileged_transition")
	}

	if atm.isConfinedDomain(trans.SourceType) {
		conditions = append(conditions, "confined_source")
	}

	return conditions
}

// isPrivilegedDomain checks if a domain has elevated privileges
func (atm *AutoTransitionMapper) isPrivilegedDomain(domain string) bool {
	privilegedPatterns := []string{
		"admin",
		"sysadm",
		"secadm",
		"auditadm",
		"root",
		"system",
	}

	domainLower := strings.ToLower(domain)
	for _, pattern := range privilegedPatterns {
		if strings.Contains(domainLower, pattern) {
			return true
		}
	}

	return false
}

// isConfinedDomain checks if a domain is confined (restricted)
func (atm *AutoTransitionMapper) isConfinedDomain(domain string) bool {
	// First check for domains that are explicitly unconfined
	unconfined := []string{
		"unconfined",
		"system",
		"kernel",
	}

	domainLower := strings.ToLower(domain)
	for _, pattern := range unconfined {
		if strings.Contains(domainLower, pattern) {
			return false
		}
	}

	// Then check for confined patterns
	confinedPatterns := []string{
		"user",
		"staff",
		"guest",
		"confined",
	}

	for _, pattern := range confinedPatterns {
		if strings.Contains(domainLower, pattern) {
			return true
		}
	}

	return false
}

// GenerateTransitionRules generates all necessary rules for auto transition
// Returns: allow rules, type_transition rule, and interface calls
func (atm *AutoTransitionMapper) GenerateTransitionRules(autoRule AutoTransitionRule) (
	[]models.AllowRule,
	models.TypeTransition,
	[]string,
) {
	allowRules := []models.AllowRule{}

	// Rule 1: Source domain can execute entry point
	allowRules = append(allowRules, models.AllowRule{
		SourceType:  autoRule.SourceDomain,
		TargetType:  autoRule.EntryPoint,
		Class:       "file",
		Permissions: []string{"execute", "read", "getattr", "open"},
	})

	// Rule 2: Target domain can use entry point as entrypoint
	allowRules = append(allowRules, models.AllowRule{
		SourceType:  autoRule.TargetDomain,
		TargetType:  autoRule.EntryPoint,
		Class:       "file",
		Permissions: []string{"entrypoint"},
	})

	// Rule 3: Source domain can transition to target domain
	allowRules = append(allowRules, models.AllowRule{
		SourceType:  autoRule.SourceDomain,
		TargetType:  autoRule.TargetDomain,
		Class:       "process",
		Permissions: []string{"transition"},
	})

	// Rule 4: Target domain can be entered
	allowRules = append(allowRules, models.AllowRule{
		SourceType:  autoRule.TargetDomain,
		TargetType:  autoRule.SourceDomain,
		Class:       "process",
		Permissions: []string{"sigchld"},
	})

	// Rule 5: Target domain needs basic process permissions
	allowRules = append(allowRules, models.AllowRule{
		SourceType:  autoRule.TargetDomain,
		TargetType:  autoRule.TargetDomain,
		Class:       "process",
		Permissions: []string{"fork", "sigchld", "signal"},
	})

	// Type transition rule
	typeTransition := models.TypeTransition{
		SourceType: autoRule.SourceDomain,
		TargetType: autoRule.EntryPoint,
		Class:      "process",
		NewType:    autoRule.TargetDomain,
	}

	// Interface calls (optional, for modular policy)
	interfaceCalls := []string{
		fmt.Sprintf("domain_auto_trans(%s, %s, %s)", autoRule.SourceDomain, autoRule.EntryPoint, autoRule.TargetDomain),
	}

	return allowRules, typeTransition, interfaceCalls
}

// ValidateTransitionPath validates a domain transition path
func (atm *AutoTransitionMapper) ValidateTransitionPath(
	path []string,
	transitions []AutoTransitionRule,
) TransitionPath {
	if len(path) < 2 {
		return TransitionPath{
			Domains: path,
			Valid:   false,
			Reason:  "path must have at least 2 domains",
		}
	}

	// Build transition map
	transMap := make(map[string]map[string]bool)
	for _, trans := range transitions {
		if transMap[trans.SourceDomain] == nil {
			transMap[trans.SourceDomain] = make(map[string]bool)
		}
		transMap[trans.SourceDomain][trans.TargetDomain] = true
	}

	// Validate each step in the path
	for i := 0; i < len(path)-1; i++ {
		source := path[i]
		target := path[i+1]

		if transMap[source] == nil || !transMap[source][target] {
			return TransitionPath{
				Domains: path,
				Valid:   false,
				Reason:  fmt.Sprintf("no transition from %s to %s", source, target),
			}
		}

		// Note: We don't check for privilege escalation here because if the
		// transition is in the map, it means it was explicitly allowed by policy
	}

	return TransitionPath{
		Domains: path,
		Valid:   true,
		Reason:  "valid transition path",
	}
}

// OptimizeTransitions removes redundant transition rules
func (atm *AutoTransitionMapper) OptimizeTransitions(rules []AutoTransitionRule) []AutoTransitionRule {
	// Remove duplicate rules
	seen := make(map[string]bool)
	optimized := make([]AutoTransitionRule, 0)

	for _, rule := range rules {
		key := fmt.Sprintf("%s->%s:%s", rule.SourceDomain, rule.TargetDomain, rule.EntryPoint)
		if !seen[key] {
			optimized = append(optimized, rule)
			seen[key] = true
		}
	}

	return optimized
}

// GenerateTransitionGraph generates a graph of all domain transitions
type TransitionGraph struct {
	Nodes []string                      // All domains
	Edges map[string][]string           // domain -> [reachable domains]
	Rules map[string]AutoTransitionRule // edge key -> rule
}

// BuildTransitionGraph builds a transition graph from rules
func (atm *AutoTransitionMapper) BuildTransitionGraph(rules []AutoTransitionRule) *TransitionGraph {
	graph := &TransitionGraph{
		Nodes: make([]string, 0),
		Edges: make(map[string][]string),
		Rules: make(map[string]AutoTransitionRule),
	}

	// Collect all unique domains
	domainSet := make(map[string]bool)
	for _, rule := range rules {
		domainSet[rule.SourceDomain] = true
		domainSet[rule.TargetDomain] = true
	}

	for domain := range domainSet {
		graph.Nodes = append(graph.Nodes, domain)
	}

	// Build edges
	for _, rule := range rules {
		graph.Edges[rule.SourceDomain] = append(graph.Edges[rule.SourceDomain], rule.TargetDomain)
		edgeKey := fmt.Sprintf("%s->%s", rule.SourceDomain, rule.TargetDomain)
		graph.Rules[edgeKey] = rule
	}

	return graph
}

// FindTransitionPath finds a transition path between two domains
func (atm *AutoTransitionMapper) FindTransitionPath(
	graph *TransitionGraph,
	source, target string,
) []string {
	// BFS to find shortest path
	queue := [][]string{{source}}
	visited := make(map[string]bool)
	visited[source] = true

	for len(queue) > 0 {
		path := queue[0]
		queue = queue[1:]

		current := path[len(path)-1]

		if current == target {
			return path
		}

		for _, next := range graph.Edges[current] {
			if !visited[next] {
				visited[next] = true
				newPath := make([]string, len(path)+1)
				copy(newPath, path)
				newPath[len(path)] = next
				queue = append(queue, newPath)
			}
		}
	}

	return nil // No path found
}
