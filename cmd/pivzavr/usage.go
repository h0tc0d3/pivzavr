package main

import (
	"bytes"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/pborman/getopt/v2"
)

// printUsage prints the usage line and the option list to w. getopt lists every
// option in the usage line and sorts the option list by name, so both are
// adjusted before they are printed: the options that change or recover the
// secrets and the data of a smart card are left out of the usage line, which
// describes the plain invocations, and they are moved behind the --reset option
// so that they are described one after the other.
func printUsage(w io.Writer) {
	var sorted bytes.Buffer
	getopt.PrintUsage(&sorted)

	usage := usageLineWithoutAdmin(sorted.String())
	for _, block := range orderUsage(usageBlocks(usage)) {
		for _, line := range block {
			_, _ = io.WriteString(w, line)
		}
	}
}

// adminOptions are the options that change or recover the secrets and the data
// of a smart card, in the order they are described in the option list.
var adminOptions = []string{
	"--unlock",
	"--set-pin",
	"--set-puk",
	"--set-chuid",
	"--set-ccc",
	"--set-management-key",
	"--protect",
	"--random",
}

// usageLineOptions are the options that the usage line leaves out, so that it
// describes the plain invocations only. The administration options are moved
// behind --reset in the option list, while --reset restores the smart card and
// --update-trust refreshes the trust store of the configuration directory;
// neither of them reads or signs an input.
var usageLineOptions = append([]string{"--reset", "--update-trust"}, adminOptions...)

// usageLineWithoutAdmin removes the options that are not a plain invocation
// from the usage line that getopt prints, so that the line describes the plain
// invocations only.
func usageLineWithoutAdmin(usage string) string {
	line, rest, found := strings.Cut(usage, "\n")
	for _, option := range usageLineOptions {
		line = removeUsageOption(line, option)
	}
	line = strings.Join(strings.Fields(line), " ")

	if !found {
		return line
	}
	return line + "\n" + rest
}

// removeUsageOption removes the bracketed option named option, together with its
// parameter, from the usage line that getopt prints. The brackets are counted,
// so that a parameter which is bracketed as well, as getopt writes it in the
// option list, is removed with the option. A line that does not name the option
// is returned unchanged.
func removeUsageOption(line, option string) string {
	start := strings.Index(line, "["+option)
	if start < 0 {
		return line
	}

	depth := 0
	for i := start; i < len(line); i++ {
		switch line[i] {
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				return line[:start] + line[i+1:]
			}
		}
	}
	return line
}

// orderUsage moves the administration options behind --reset, so that the
// options that change a smart card are described one after the other.
func orderUsage(blocks [][]string) [][]string {
	var moved [][]string
	rest := blocks
	for _, option := range adminOptions {
		for i, block := range rest {
			if !optionNames(block, option) {
				continue
			}
			moved = append(moved, block)
			rest = append(rest[:i:i], rest[i+1:]...)
			break
		}
	}
	if len(moved) == 0 {
		return blocks
	}

	ordered := make([][]string, 0, len(blocks))
	inserted := false
	for _, block := range rest {
		ordered = append(ordered, block)
		if !inserted && optionNames(block, "--reset") {
			ordered = append(ordered, moved...)
			inserted = true
		}
	}
	if !inserted {
		ordered = append(ordered, moved...)
	}
	return ordered
}

// optionNames reports whether the option part of a block names option. getopt
// writes the parameter of an option after an equals sign, which is not part of
// the name, so the character that follows the name is inspected as well.
func optionNames(block []string, option string) bool {
	name := optionName(block)
	i := strings.Index(name, option)
	if i < 0 {
		return false
	}
	rest := name[i+len(option):]
	return rest == "" || rest[0] < 'a' || rest[0] > 'z'
}

// usageBlocks splits the text printed by getopt into the usage line and one
// block per option. A block holds every line getopt uses for an option,
// including the wrapped help text lines, so blocks can be moved as a whole.
func usageBlocks(usage string) [][]string {
	var blocks [][]string
	var block []string
	for _, line := range strings.SplitAfter(usage, "\n") {
		if line == "" {
			continue
		}
		if len(block) > 0 && startsOption(line) {
			blocks = append(blocks, block)
			block = nil
		}
		block = append(block, line)
	}
	if len(block) > 0 {
		blocks = append(blocks, block)
	}
	return blocks
}

// startsOption reports whether line begins a new option in the text printed by
// getopt. getopt indents the name of an option by at most five spaces while
// the wrapped help text of an option is indented by more.
func startsOption(line string) bool {
	trimmed := strings.TrimLeft(line, " ")
	indent := len(line) - len(trimmed)
	return indent > 0 && indent <= 5 && len(strings.TrimSpace(trimmed)) > 0
}

// optionName returns the option part of a block, such as "-r, --reset" or
// "--unlock", or "" when the block is not an option. The option part ends where
// getopt starts the aligned help text, which is separated by two spaces, while
// a short and a long option are separated by one.
func optionName(block []string) string {
	if len(block) == 0 {
		return ""
	}
	line := strings.TrimRight(block[0], "\n")
	if !strings.HasPrefix(line, " ") {
		return ""
	}
	line = strings.TrimLeft(line, " ")
	if i := strings.Index(line, "  "); i >= 0 {
		line = line[:i]
	}
	return line
}

// wrap breaks text into lines that are at most width characters wide, at the
// last space before the limit so that words are kept whole. It counts
// characters, not bytes, so a translated description is wrapped at the same
// width as the English one.
func wrap(text string, width int) string {
	words := strings.Fields(text)
	if len(words) == 0 {
		return ""
	}
	var lines []string
	line := words[0]
	for _, word := range words[1:] {
		if utf8.RuneCountInString(line)+1+utf8.RuneCountInString(word) > width {
			lines = append(lines, line)
			line = word
		} else {
			line += " " + word
		}
	}
	lines = append(lines, line)
	return strings.Join(lines, "\n")
}
