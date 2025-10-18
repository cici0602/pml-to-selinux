package models

// Constraint represents a SELinux constraint
type Constraint struct {
	Type        string   // "constrain" or "mlsconstrain"
	Classes     []string // Object classes this constraint applies to
	Permissions []string // Permissions this constraint applies to
	Expression  string   // The constraint expression
}

// RoleTransitionConstraint represents constraints on role transitions
type RoleTransitionConstraint struct {
	FromRole     string
	ToRole       string
	Class        string
	AllowedTypes []string // Types that allow this transition
}

// UserRoleConstraint represents constraints on user-role assignments
type UserRoleConstraint struct {
	User  string
	Roles []string // Allowed roles for this user
}

// DomainTransitionConstraint represents constraints on domain transitions
type DomainTransitionConstraint struct {
	SourceDomain string
	TargetDomain string
	EntryPoint   string   // Entry point executable type
	Conditions   []string // Additional conditions
}

// AddConstraint adds a constraint to the policy
func (p *SELinuxPolicy) AddConstraint(c Constraint) {
	if p.Constraints == nil {
		p.Constraints = make([]Constraint, 0)
	}
	p.Constraints = append(p.Constraints, c)
}
