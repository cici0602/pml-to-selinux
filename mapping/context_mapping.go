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
func (pm *PathMapper) ConvertToSELinuxPattern(casbinPath string) string {
	// Check for custom mapping first
	if customPattern, ok := pm.customMappings[casbinPath]; ok {
		return customPattern
	}

	pattern := casbinPath

	// Handle recursive patterns ending with /*
	if strings.HasSuffix(pattern, "/*") {
		// /var/www/* → /var/www(/.*)?
		base := strings.TrimSuffix(pattern, "/*")
		// Handle wildcards in the base path first
		if strings.Contains(base, "*") {
			base = escapeRegexCharsPreservingWildcards(base)
			base = strings.ReplaceAll(base, "*", "[^/]+")
		} else {
			base = escapeRegexChars(base)
		}
		return base + "(/.*)?"
	}

	// Escape special regex characters except * and ?
	pattern = escapeRegexCharsPreservingWildcards(casbinPath)

	// Convert middle wildcards
	// /etc/*.conf → /etc/[^/]+\.conf
	pattern = strings.ReplaceAll(pattern, "*", "[^/]+")

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

	// Check for known directory patterns
	dirPatterns := []string{"/bin", "/sbin", "/lib", "/etc", "/var", "/usr", "/opt", "/srv"}
	for _, dirPattern := range dirPatterns {
		if path == dirPattern || strings.HasPrefix(path, dirPattern+"/") {
			// Check if it's a config file
			if strings.HasSuffix(path, ".conf") || strings.HasSuffix(path, ".cfg") {
				return "regular file"
			}
		}
	}

	// Check file extensions for regular files
	fileExtensions := []string{".conf", ".cfg", ".txt", ".log", ".html", ".htm", ".php", ".py", ".sh", ".so", ".a"}
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
