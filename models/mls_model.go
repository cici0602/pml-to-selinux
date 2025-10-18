package models

import (
	"fmt"
	"strconv"
	"strings"
)

// SecurityLevel represents a MLS/MCS security level
// Format: s<sensitivity>[:c<categories>]
// Examples: s0, s1:c0, s2:c0.c5, s3:c0,c2,c5
type SecurityLevel struct {
	Sensitivity int   // 0-15 (s0-s15)
	Categories  []int // 0-1023 (c0-c1023)
}

// SecurityRange represents a MLS/MCS security range
// Format: <low>[-<high>]
// Examples: s0, s0-s1, s0:c0.c255-s1:c0.c255
type SecurityRange struct {
	Low  SecurityLevel
	High SecurityLevel // If not specified, same as Low
}

// MLSContext represents a complete SELinux security context with MLS/MCS
// Format: user:role:type:level
// Examples:
//   - system_u:object_r:httpd_sys_content_t:s0
//   - user_u:user_r:user_t:s0-s0:c0.c1023
type MLSContext struct {
	User  string
	Role  string
	Type  string
	Level SecurityRange
}

// MLSConstraint represents a MLS constraint rule
// Example: mlsconstrain file { read } (l1 dom l2);
type MLSConstraint struct {
	Classes     []string // Object classes
	Permissions []string // Permissions
	Expression  string   // Constraint expression using operators like dom, domby, eq, incomp
}

// NewSecurityLevel creates a new security level
func NewSecurityLevel(sensitivity int, categories ...int) SecurityLevel {
	return SecurityLevel{
		Sensitivity: sensitivity,
		Categories:  categories,
	}
}

// NewSecurityRange creates a new security range
func NewSecurityRange(low, high SecurityLevel) SecurityRange {
	return SecurityRange{
		Low:  low,
		High: high,
	}
}

// NewSingleLevelRange creates a single-level range (low == high)
func NewSingleLevelRange(level SecurityLevel) SecurityRange {
	return SecurityRange{
		Low:  level,
		High: level,
	}
}

// String returns the string representation of a SecurityLevel
// Examples: s0, s1:c0, s2:c0.c5, s3:c0,c2,c5
func (sl SecurityLevel) String() string {
	if len(sl.Categories) == 0 {
		return fmt.Sprintf("s%d", sl.Sensitivity)
	}

	// Format categories
	catStr := formatCategories(sl.Categories)
	return fmt.Sprintf("s%d:%s", sl.Sensitivity, catStr)
}

// String returns the string representation of a SecurityRange
// Examples: s0, s0-s1, s0:c0.c255-s1:c0.c255
func (sr SecurityRange) String() string {
	if sr.Low.Equals(sr.High) {
		return sr.Low.String()
	}
	return fmt.Sprintf("%s-%s", sr.Low.String(), sr.High.String())
}

// String returns the string representation of a MLSContext
// Example: system_u:object_r:httpd_sys_content_t:s0-s0:c0.c1023
func (mc MLSContext) String() string {
	return fmt.Sprintf("%s:%s:%s:%s", mc.User, mc.Role, mc.Type, mc.Level.String())
}

// Equals checks if two security levels are equal
func (sl SecurityLevel) Equals(other SecurityLevel) bool {
	if sl.Sensitivity != other.Sensitivity {
		return false
	}
	if len(sl.Categories) != len(other.Categories) {
		return false
	}
	for i, cat := range sl.Categories {
		if cat != other.Categories[i] {
			return false
		}
	}
	return true
}

// Dominates checks if this level dominates (is >= to) another level
// A level dominates another if:
// 1. sensitivity >= other.sensitivity
// 2. all categories in other are included in this level
func (sl SecurityLevel) Dominates(other SecurityLevel) bool {
	if sl.Sensitivity < other.Sensitivity {
		return false
	}

	// Check if all categories in other are in this level
	catSet := make(map[int]bool)
	for _, cat := range sl.Categories {
		catSet[cat] = true
	}

	for _, cat := range other.Categories {
		if !catSet[cat] {
			return false
		}
	}

	return true
}

// Incomparable checks if two levels are incomparable
// Two levels are incomparable if neither dominates the other
func (sl SecurityLevel) Incomparable(other SecurityLevel) bool {
	return !sl.Dominates(other) && !other.Dominates(sl)
}

// IsValid validates a security level
func (sl SecurityLevel) IsValid() bool {
	// Sensitivity must be 0-15
	if sl.Sensitivity < 0 || sl.Sensitivity > 15 {
		return false
	}

	// Categories must be 0-1023 and sorted
	for i, cat := range sl.Categories {
		if cat < 0 || cat > 1023 {
			return false
		}
		if i > 0 && cat <= sl.Categories[i-1] {
			return false // Not sorted or has duplicates
		}
	}

	return true
}

// IsValid validates a security range
func (sr SecurityRange) IsValid() bool {
	if !sr.Low.IsValid() || !sr.High.IsValid() {
		return false
	}

	// Low must dominate or equal high (wait, this seems backward)
	// Actually in SELinux: low sensitivity <= high sensitivity
	if sr.Low.Sensitivity > sr.High.Sensitivity {
		return false
	}

	return true
}

// formatCategories formats a slice of category numbers
// Examples: [0] -> "c0", [0,1,2] -> "c0.c2", [0,2,5] -> "c0,c2,c5"
func formatCategories(categories []int) string {
	if len(categories) == 0 {
		return ""
	}

	// Check if it's a continuous range
	if isContinuousRange(categories) {
		return fmt.Sprintf("c%d.c%d", categories[0], categories[len(categories)-1])
	}

	// Format as comma-separated list
	parts := make([]string, len(categories))
	for i, cat := range categories {
		parts[i] = fmt.Sprintf("c%d", cat)
	}
	return strings.Join(parts, ",")
}

// isContinuousRange checks if categories form a continuous range
func isContinuousRange(categories []int) bool {
	if len(categories) <= 1 {
		return false
	}

	for i := 1; i < len(categories); i++ {
		if categories[i] != categories[i-1]+1 {
			return false
		}
	}
	return true
}

// ParseSecurityLevel parses a security level string
// Examples: "s0", "s1:c0", "s2:c0.c5", "s3:c0,c2,c5"
func ParseSecurityLevel(s string) (SecurityLevel, error) {
	parts := strings.Split(s, ":")
	if len(parts) == 0 || len(parts) > 2 {
		return SecurityLevel{}, fmt.Errorf("invalid security level format: %s", s)
	}

	// Parse sensitivity
	if !strings.HasPrefix(parts[0], "s") {
		return SecurityLevel{}, fmt.Errorf("sensitivity must start with 's': %s", parts[0])
	}
	sensitivity, err := strconv.Atoi(parts[0][1:])
	if err != nil {
		return SecurityLevel{}, fmt.Errorf("invalid sensitivity: %s", parts[0])
	}

	level := SecurityLevel{
		Sensitivity: sensitivity,
		Categories:  []int{},
	}

	// Parse categories if present
	if len(parts) == 2 {
		cats, err := parseCategories(parts[1])
		if err != nil {
			return SecurityLevel{}, err
		}
		level.Categories = cats
	}

	if !level.IsValid() {
		return SecurityLevel{}, fmt.Errorf("invalid security level: %s", s)
	}

	return level, nil
}

// ParseSecurityRange parses a security range string
// Examples: "s0", "s0-s1", "s0:c0.c255-s1:c0.c255"
func ParseSecurityRange(s string) (SecurityRange, error) {
	parts := strings.Split(s, "-")
	if len(parts) == 0 || len(parts) > 2 {
		return SecurityRange{}, fmt.Errorf("invalid security range format: %s", s)
	}

	low, err := ParseSecurityLevel(parts[0])
	if err != nil {
		return SecurityRange{}, fmt.Errorf("invalid low level: %w", err)
	}

	high := low
	if len(parts) == 2 {
		high, err = ParseSecurityLevel(parts[1])
		if err != nil {
			return SecurityRange{}, fmt.Errorf("invalid high level: %w", err)
		}
	}

	sr := SecurityRange{Low: low, High: high}
	if !sr.IsValid() {
		return SecurityRange{}, fmt.Errorf("invalid security range: %s", s)
	}

	return sr, nil
}

// parseCategories parses category string
// Examples: "c0", "c0.c5", "c0,c2,c5"
func parseCategories(s string) ([]int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return []int{}, nil
	}

	// Check for range format: c0.c5
	if strings.Contains(s, ".") {
		parts := strings.Split(s, ".")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid category range format: %s", s)
		}

		start, err := parseSingleCategory(parts[0])
		if err != nil {
			return nil, err
		}

		end, err := parseSingleCategory(parts[1])
		if err != nil {
			return nil, err
		}

		if start > end {
			return nil, fmt.Errorf("invalid category range: start > end")
		}

		// Generate range
		cats := make([]int, end-start+1)
		for i := range cats {
			cats[i] = start + i
		}
		return cats, nil
	}

	// Parse comma-separated list
	parts := strings.Split(s, ",")
	cats := make([]int, 0, len(parts))
	for _, part := range parts {
		cat, err := parseSingleCategory(strings.TrimSpace(part))
		if err != nil {
			return nil, err
		}
		cats = append(cats, cat)
	}

	// Sort and deduplicate
	cats = sortAndDeduplicate(cats)

	return cats, nil
}

// parseSingleCategory parses a single category like "c0"
func parseSingleCategory(s string) (int, error) {
	if !strings.HasPrefix(s, "c") {
		return 0, fmt.Errorf("category must start with 'c': %s", s)
	}
	cat, err := strconv.Atoi(s[1:])
	if err != nil {
		return 0, fmt.Errorf("invalid category: %s", s)
	}
	if cat < 0 || cat > 1023 {
		return 0, fmt.Errorf("category out of range [0-1023]: %d", cat)
	}
	return cat, nil
}

// sortAndDeduplicate sorts a slice of ints and removes duplicates
func sortAndDeduplicate(arr []int) []int {
	if len(arr) == 0 {
		return arr
	}

	// Simple bubble sort for small arrays (typically categories are few)
	for i := 0; i < len(arr); i++ {
		for j := i + 1; j < len(arr); j++ {
			if arr[i] > arr[j] {
				arr[i], arr[j] = arr[j], arr[i]
			}
		}
	}

	// Remove duplicates
	result := []int{arr[0]}
	for i := 1; i < len(arr); i++ {
		if arr[i] != arr[i-1] {
			result = append(result, arr[i])
		}
	}

	return result
}

// DefaultSecurityLevel returns the default security level s0
func DefaultSecurityLevel() SecurityLevel {
	return SecurityLevel{Sensitivity: 0, Categories: []int{}}
}

// DefaultSecurityRange returns the default security range s0
func DefaultSecurityRange() SecurityRange {
	return NewSingleLevelRange(DefaultSecurityLevel())
}
