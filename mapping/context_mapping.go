package mapping

import (
	"fmt"
	"regexp"
	"strings"
)

// PathMapper handles conversion from Casbin path patterns to SELinux path patterns
type PathMapper struct {
	// Custom path pattern mappings
	customMappings map[string]string
}

// NewPathMapper creates a new PathMapper instance
func NewPathMapper() *PathMapper {
	return &PathMapper{
		customMappings: make(map[string]string),
	}
}

// AddCustomMapping adds a custom path pattern mapping
func (pm *PathMapper) AddCustomMapping(casbinPattern, selinuxPattern string) {
	pm.customMappings[casbinPattern] = selinuxPattern
}

// ConvertToSELinuxPattern converts a Casbin path pattern to SELinux file context pattern
// Examples:
//
//	/var/www/*           →  /var/www(/.*)?
//	/etc/*.conf          →  /etc/[^/]+\.conf
//	/var/log/httpd/*     →  /var/log/httpd(/.*)?
//	/home/*/public_html  →  /home/[^/]+/public_html
//	/path/**/file        →  /path/.*/file (recursive subdirs)
//	/etc/[a-z]*.conf     →  /etc/[a-z][^/]*\.conf (char class)
//	/var/{log,tmp}/*     →  /var/(log|tmp)(/.*)? (brace expansion)
func (pm *PathMapper) ConvertToSELinuxPattern(casbinPath string) string {
	// Check for custom mapping first
	if customPattern, ok := pm.customMappings[casbinPath]; ok {
		return customPattern
	}

	pattern := casbinPath

	// Handle brace expansion {a,b,c} → (a|b|c) BEFORE escaping
	hasBraceExpansion := strings.Contains(pattern, "{")
	pattern = pm.expandBraces(pattern)

	// Handle double-star /** pattern BEFORE handling /* (as /** can contain /*)
	if strings.Contains(pattern, "/**") {
		return pm.handleDoubleStarPattern(pattern)
	}

	// Handle recursive patterns ending with /*
	if strings.HasSuffix(pattern, "/*") {
		// /var/www/* → /var/www(/.*)?
		base := strings.TrimSuffix(pattern, "/*")
		// Escape the base, but preserve regex patterns from brace expansion
		base = pm.escapePreservingPatterns(base, hasBraceExpansion)
		return base + "(/.*)?"
	}

	// Escape special regex characters except * and ? and character classes
	if hasBraceExpansion {
		pattern = pm.escapePreservingPatterns(pattern, true)
	} else {
		pattern = escapeRegexCharsPreservingWildcardsAndCharClasses(pattern)
	}

	// Convert middle wildcards
	// /etc/*.conf → /etc/[^/]+\.conf
	// But preserve [^/]* if preceded by character class
	pattern = pm.convertWildcards(pattern)

	// Convert ? to single character match
	pattern = strings.ReplaceAll(pattern, "?", ".")

	return pattern
}

// escapeRegexChars escapes special regex characters except * and ?
func escapeRegexChars(s string) string {
	// Escape backslash first to avoid double-escaping
	result := strings.ReplaceAll(s, "\\", "\\\\")

	// Then escape other special characters
	specialChars := []string{".", "+", "(", ")", "[", "]", "{", "}", "^", "$", "|", "-"}
	for _, char := range specialChars {
		result = strings.ReplaceAll(result, char, "\\"+char)
	}

	return result
}

// escapeRegexCharsPreservingWildcards escapes regex chars but preserves * and ?
func escapeRegexCharsPreservingWildcards(s string) string {
	// Escape backslash first to avoid double-escaping
	result := strings.ReplaceAll(s, "\\", "\\\\")

	// Then escape other special characters (but keep * and ? for later processing)
	specialChars := []string{".", "+", "(", ")", "[", "]", "{", "}", "^", "$", "|", "-"}
	for _, char := range specialChars {
		result = strings.ReplaceAll(result, char, "\\"+char)
	}

	// * and ? are left as-is for further processing
	return result
}

// escapeRegexCharsPreservingWildcardsAndCharClasses escapes regex chars but preserves *, ?, and [...]
func escapeRegexCharsPreservingWildcardsAndCharClasses(s string) string {
	// Protect both character classes [...] and parentheses from brace expansion (...)
	// First, protect parentheses and pipes from brace expansion
	s = strings.ReplaceAll(s, "(", "__LPAREN__")
	s = strings.ReplaceAll(s, ")", "__RPAREN__")
	s = strings.ReplaceAll(s, "|", "__PIPE__")

	// Use regex to protect character classes temporarily
	charClassRegex := regexp.MustCompile(`\[([^\]]+)\]`)

	// Find all character classes
	matches := charClassRegex.FindAllStringSubmatchIndex(s, -1)

	// Build result by processing non-character-class parts
	var result strings.Builder
	lastIndex := 0

	for _, match := range matches {
		// Process text before character class
		beforeClass := s[lastIndex:match[0]]
		result.WriteString(escapeRegexCharsPreservingWildcards(beforeClass))

		// Add character class as-is
		result.WriteString(s[match[0]:match[1]])

		lastIndex = match[1]
	}

	// Process remaining text after last character class
	if lastIndex < len(s) {
		result.WriteString(escapeRegexCharsPreservingWildcards(s[lastIndex:]))
	}

	// Restore parentheses and pipes
	finalResult := result.String()
	finalResult = strings.ReplaceAll(finalResult, "__LPAREN__", "(")
	finalResult = strings.ReplaceAll(finalResult, "__RPAREN__", ")")
	finalResult = strings.ReplaceAll(finalResult, "__PIPE__", "|")

	return finalResult
}

// IsDirectoryPattern checks if a path pattern represents a directory
func (pm *PathMapper) IsDirectoryPattern(path string) bool {
	// Ends with / indicates directory
	if strings.HasSuffix(path, "/") {
		return true
	}

	// Ends with /* likely refers to directory contents
	if strings.HasSuffix(path, "/*") {
		return true
	}

	// Common directory paths without wildcards
	dirPaths := []string{"/bin", "/sbin", "/lib", "/lib64", "/etc", "/var", "/usr", "/opt", "/srv", "/home"}
	for _, dirPath := range dirPaths {
		if path == dirPath {
			return true
		}
	}

	return false
}

// IsRecursivePattern checks if a path pattern should match recursively
func (pm *PathMapper) IsRecursivePattern(path string) bool {
	// /path/to/dir/* is recursive
	return strings.HasSuffix(path, "/*")
}

// GenerateRecursivePatterns generates both directory and file patterns for recursive matching
// For a path like /var/www/*, it generates:
// - /var/www(/.*)? for all files and subdirectories
// This allows SELinux to match the directory and all its contents recursively
func (pm *PathMapper) GenerateRecursivePatterns(path string) []PathPattern {
	patterns := []PathPattern{}

	if !pm.IsRecursivePattern(path) {
		// Not recursive, return single pattern
		sePattern := pm.ConvertToSELinuxPattern(path)
		patterns = append(patterns, PathPattern{
			Pattern:  sePattern,
			FileType: pm.InferFileType(path),
		})
		return patterns
	}

	// Extract base path
	basePath := ExtractBasePath(path)
	escapedBase := escapeRegexChars(basePath)

	// Pattern for all files and subdirectories: /base(/.*)?
	patterns = append(patterns, PathPattern{
		Pattern:  escapedBase + "(/.*)?",
		FileType: "all files",
	})

	return patterns
}

// PathPattern represents a SELinux file context pattern with its file type
type PathPattern struct {
	Pattern  string // SELinux regex pattern
	FileType string // File type (directory, regular file, etc.)
}

// InferFileType infers the SELinux file type specification from the path
// Returns one of: "regular file", "directory", "symlink", "socket", "pipe", "block", "char"
func (pm *PathMapper) InferFileType(path string) string {
	// If path ends with /, it's a directory
	if strings.HasSuffix(path, "/") {
		return "directory"
	}

	// If path ends with /*, it likely refers to contents (which could be any type)
	// Default to "-d" for directory in these cases
	if strings.HasSuffix(path, "/*") {
		return "all files" // This will generate pattern without file type specifier
	}

	// Check for device files (block and character devices)
	if strings.HasPrefix(path, "/dev/") {
		// Block devices: disks, partitions
		if strings.Contains(path, "sd") || strings.Contains(path, "hd") ||
			strings.Contains(path, "vd") || strings.Contains(path, "nvme") ||
			strings.Contains(path, "loop") || strings.Contains(path, "dm-") {
			return "block"
		}
		// Character devices: tty, pts, random, null, zero
		if strings.Contains(path, "tty") || strings.Contains(path, "pts") ||
			strings.Contains(path, "random") || strings.Contains(path, "urandom") ||
			path == "/dev/null" || path == "/dev/zero" || strings.Contains(path, "console") {
			return "char"
		}
		// Default device type
		return "char"
	}

	// Check for socket files
	if strings.Contains(path, ".sock") || strings.Contains(path, ".socket") ||
		strings.HasPrefix(path, "/run/") || strings.HasPrefix(path, "/var/run/") {
		// Common socket locations
		if strings.HasSuffix(path, ".sock") || strings.HasSuffix(path, ".socket") ||
			strings.Contains(path, "socket") || strings.Contains(path, "/dbus/") {
			return "socket"
		}
	}

	// Check for named pipes (FIFOs)
	if strings.Contains(path, ".fifo") || strings.Contains(path, "/pipe/") {
		return "pipe"
	}

	// Check for symbolic links
	if strings.Contains(path, "/link/") || path == "/etc/alternatives" ||
		(strings.HasPrefix(path, "/etc/alternatives/") && !strings.Contains(path, ".")) {
		return "symlink"
	}

	// Check for known directory patterns
	dirPatterns := []string{"/bin", "/sbin", "/lib", "/lib64", "/etc", "/var", "/usr", "/opt", "/srv", "/home"}
	for _, dirPattern := range dirPatterns {
		if path == dirPattern || strings.HasPrefix(path, dirPattern+"/") {
			// Check if it's a config file
			if strings.HasSuffix(path, ".conf") || strings.HasSuffix(path, ".cfg") {
				return "regular file"
			}
		}
	}

	// Check file extensions for regular files
	fileExtensions := []string{".conf", ".cfg", ".txt", ".log", ".html", ".htm", ".php", ".py", ".sh", ".so", ".a", ".service", ".target", ".mount", ".timer"}
	for _, ext := range fileExtensions {
		if strings.HasSuffix(path, ext) || strings.Contains(path, ext) {
			return "regular file"
		}
	}

	// Default to all files (no file type specifier)
	return "all files"
}

// GetFileTypeSpecifier returns the SELinux file type specifier for .fc files
// Returns the suffix to add before the context (e.g., "", " -d", " -l", etc.)
func GetFileTypeSpecifier(fileType string) string {
	switch fileType {
	case "regular file":
		return " --"
	case "directory":
		return " -d"
	case "symlink":
		return " -l"
	case "socket":
		return " -s"
	case "pipe":
		return " -p"
	case "block":
		return " -b"
	case "char":
		return " -c"
	case "all files":
		return ""
	default:
		return ""
	}
}

// ValidatePattern validates if a pattern is a valid SELinux file context pattern
func (pm *PathMapper) ValidatePattern(pattern string) error {
	// Check if pattern is a valid regex
	_, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid regex pattern: %w", err)
	}

	// Check if pattern starts with /
	if !strings.HasPrefix(pattern, "/") {
		return fmt.Errorf("pattern must start with /: %s", pattern)
	}

	return nil
}

// NormalizePath normalizes a path by removing trailing slashes and double slashes
func NormalizePath(path string) string {
	if path == "" {
		return ""
	}

	// Handle root path specially
	if path == "/" {
		return path
	}

	// Replace multiple consecutive slashes with single slash
	normalized := ""
	prevChar := byte(0)
	for i := 0; i < len(path); i++ {
		char := path[i]
		if char == '/' && prevChar == '/' {
			continue // Skip consecutive slashes
		}
		normalized += string(char)
		prevChar = char
	}

	// Remove trailing slash (except for root)
	normalized = strings.TrimRight(normalized, "/")
	if normalized == "" {
		return "/"
	}

	return normalized
}

// ExtractBasePath extracts the base path without wildcards
// Example: /var/www/* → /var/www
func ExtractBasePath(path string) string {
	// Remove trailing /*
	if strings.HasSuffix(path, "/*") {
		return strings.TrimSuffix(path, "/*")
	}

	// Find the first wildcard
	wildcardPos := strings.IndexAny(path, "*?")
	if wildcardPos == -1 {
		return path
	}

	// Return everything before the wildcard directory
	basePath := path[:wildcardPos]
	lastSlash := strings.LastIndex(basePath, "/")
	if lastSlash > 0 {
		return basePath[:lastSlash]
	}

	return "/"
}

// expandBraces expands brace patterns like {a,b,c} into (a|b|c)
// Example: /var/{log,tmp}/* → /var/(log|tmp)/*
func (pm *PathMapper) expandBraces(path string) string {
	// Find brace patterns using regex
	braceRegex := regexp.MustCompile(`\{([^}]+)\}`)
	return braceRegex.ReplaceAllStringFunc(path, func(match string) string {
		// Extract content between braces
		content := match[1 : len(match)-1]
		// Split by comma
		alternatives := strings.Split(content, ",")
		// Trim whitespace from each alternative
		for i := range alternatives {
			alternatives[i] = strings.TrimSpace(alternatives[i])
		}
		// Join with | for regex alternation
		return "(" + strings.Join(alternatives, "|") + ")"
	})
}

// handleDoubleStarPattern handles /** patterns for recursive subdirectory matching
// Example: /usr/**/bin → /usr/.*/bin
func (pm *PathMapper) handleDoubleStarPattern(path string) string {
	// Check if path already contains regex patterns from brace expansion
	hasRegexPatterns := strings.Contains(path, "(") && strings.Contains(path, "|")

	// Check if it also ends with /*
	endsWithSlashStar := strings.HasSuffix(path, "/*")
	if endsWithSlashStar {
		// Remove the /* suffix temporarily
		path = strings.TrimSuffix(path, "/*")
	}

	// Special case: if path ends with /**, just add (/.*)?
	if strings.HasSuffix(path, "/**") {
		base := strings.TrimSuffix(path, "/**")
		// Preserve existing regex patterns
		if hasRegexPatterns {
			base = escapeRegexCharsPreservingWildcardsAndCharClasses(base)
		} else {
			base = escapeRegexChars(base)
		}
		result := base + "(/.*)?"
		// If originally ended with /*, that's already covered by (/.*)?
		return result
	}

	// Escape special characters except ** and /
	parts := strings.Split(path, "/**")
	escapedParts := make([]string, len(parts))

	for i, part := range parts {
		// Skip empty parts
		if part == "" {
			continue
		}

		// Process wildcards in each part, preserving regex patterns
		if hasRegexPatterns {
			part = escapeRegexCharsPreservingWildcardsAndCharClasses(part)
			// Need to convert remaining wildcards
			part = pm.convertWildcards(part)
		} else if strings.Contains(part, "*") {
			part = escapeRegexCharsPreservingWildcards(part)
			part = strings.ReplaceAll(part, "*", "[^/]+")
		} else {
			part = escapeRegexChars(part)
		}
		escapedParts[i] = part
	}

	// Join with .* for recursive matching
	result := strings.Join(escapedParts, "/.*")

	// Add /* pattern if it was there
	if endsWithSlashStar {
		result += "(/.*)?"
	}

	return result
}

// convertWildcards converts wildcards to regex patterns, handling character classes specially
func (pm *PathMapper) convertWildcards(path string) string {
	// First, handle character classes followed by wildcards
	// [a-z]* should become [a-z][^/]* not [a-z][^/]+
	// Use placeholder to avoid double replacement
	charClassWildcard := regexp.MustCompile(`(\[[^\]]+\])\*`)
	path = charClassWildcard.ReplaceAllString(path, "${1}__CHARWILD__")

	// Convert remaining standalone * to [^/]+
	path = strings.ReplaceAll(path, "*", "[^/]+")

	// Restore character class wildcards
	path = strings.ReplaceAll(path, "__CHARWILD__", "[^/]*")

	return path
}

// escapePreservingPatterns escapes special characters while preserving regex patterns from expansions
func (pm *PathMapper) escapePreservingPatterns(path string, preserveRegex bool) string {
	if !preserveRegex {
		return escapeRegexChars(path)
	}

	// Use the same logic as escapeRegexCharsPreservingWildcardsAndCharClasses
	// to also preserve character classes
	return escapeRegexCharsPreservingWildcardsAndCharClasses(path)
}

// MatchPattern checks if a path matches a SELinux pattern (for validation)
func (pm *PathMapper) MatchPattern(selinuxPattern, testPath string) (bool, error) {
	// Compile the pattern as a regex
	regex, err := regexp.Compile("^" + selinuxPattern + "$")
	if err != nil {
		return false, fmt.Errorf("invalid pattern: %w", err)
	}

	return regex.MatchString(testPath), nil
}

// InferContextType determines the SELinux type based on path characteristics
// This provides smart type suggestions for file contexts
func (pm *PathMapper) InferContextType(path string) string {
	// Executable directories
	if strings.HasPrefix(path, "/bin/") || strings.HasPrefix(path, "/sbin/") ||
		strings.HasPrefix(path, "/usr/bin/") || strings.HasPrefix(path, "/usr/sbin/") {
		return "bin_t"
	}

	// Library files
	if strings.HasPrefix(path, "/lib/") || strings.HasPrefix(path, "/lib64/") ||
		strings.HasPrefix(path, "/usr/lib/") {
		if strings.HasSuffix(path, ".so") || strings.Contains(path, ".so.") {
			return "lib_t"
		}
	}

	// Configuration files
	if strings.HasPrefix(path, "/etc/") {
		return "etc_t"
	}

	// Log files
	if strings.HasPrefix(path, "/var/log/") {
		return "var_log_t"
	}

	// Temporary files
	if strings.HasPrefix(path, "/tmp/") || strings.HasPrefix(path, "/var/tmp/") {
		return "tmp_t"
	}

	// Runtime files
	if strings.HasPrefix(path, "/run/") || strings.HasPrefix(path, "/var/run/") {
		return "var_run_t"
	}

	// Home directories
	if strings.HasPrefix(path, "/home/") || strings.HasPrefix(path, "/root/") {
		return "user_home_t"
	}

	// Device files
	if strings.HasPrefix(path, "/dev/") {
		return "device_t"
	}

	// Default type
	return "default_t"
}

// SplitPathPattern splits a complex pattern into base and wildcard parts
// Useful for generating more precise SELinux patterns
func (pm *PathMapper) SplitPathPattern(path string) (base, wildcard string) {
	// Find first wildcard character
	wildcardIndex := strings.IndexAny(path, "*?{")
	if wildcardIndex == -1 {
		return path, ""
	}

	// Find last slash before wildcard
	basePart := path[:wildcardIndex]
	lastSlash := strings.LastIndex(basePart, "/")
	if lastSlash == -1 {
		return "", path
	}

	return path[:lastSlash], path[lastSlash+1:]
}
