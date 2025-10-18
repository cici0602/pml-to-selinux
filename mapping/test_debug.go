package mapping

import (
"fmt"
"testing"
)

func TestDebugCharClass(t *testing.T) {
	mapper := NewPathMapper()
	input := "/etc/[a-z]*.conf"
	
	fmt.Printf("Input: %s\n", input)
	
	// Step by step
	step1 := escapeRegexCharsPreservingWildcardsAndCharClasses(input)
	fmt.Printf("After escape: %s\n", step1)
	
	step2 := mapper.convertWildcards(step1)
	fmt.Printf("After convertWildcards: %s\n", step2)
	
	result := mapper.ConvertToSELinuxPattern(input)
	fmt.Printf("Final result: %s\n", result)
}
