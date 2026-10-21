package tarantula

import (
	"fmt"
	"strings"
)

func formatData(data []byte, bytesPerLine int) string {
	var output strings.Builder
	lineStart := 0
	fmt.Fprintf(&output, "\t%08x: ", lineStart)
	for i, b := range data {
		fmt.Fprintf(&output, "%02x ", b)
		if (i+1)%bytesPerLine == 0 {
			writeCharacters(&output, data[lineStart:i+1])
			lineStart = i + 1
			fmt.Fprintf(&output, "\n\t%08x: ", lineStart)
		}
	}

	if lineStart < len(data) {
		writeCharacters(&output, data[lineStart:])
	}

	output.WriteByte('\n')
	return output.String()
}

func writeCharacters(output *strings.Builder, data []byte) {
	output.WriteByte('|')
	for _, b := range data {
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') {
			output.WriteByte(b)
		} else {
			output.WriteByte('.')
		}
	}

	output.WriteByte('|')
}
