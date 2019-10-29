package tml

import (
	"fmt"
	"io"
	"strings"
)

// Parser is used to parse a TML string into an output string containing ANSI escape codes
type Parser struct {
	writer                io.Writer
	IncludeLeadingResets  bool
	IncludeTrailingResets bool
	state                 parserState
}

type parserState struct {
	fg    string
	bg    string
	attrs attrs
}

type attrs uint8

const (
	Bold      uint8 = 1
	Dim             = 2
	Underline       = 4
	Blink           = 8
	Reverse         = 16
	Hidden          = 32
)

var resetAll = "\x1b[0m"
var resetFg = "\x1b[39m"
var resetBg = "\x1b[49m"

var attrMap = map[uint8]string{
	Bold:      "\x1b[1m",
	Dim:       "\x1b[2m",
	Underline: "\x1b[4m",
	Blink:     "\x1b[5m",
	Reverse:   "\x1b[7m",
	Hidden:    "\x1b[8m",
}

func (s *parserState) setFg(esc string) string {
	if s.fg == esc {
		return ""
	}
	s.fg = esc
	return esc
}

func (s *parserState) setBg(esc string) string {
	if s.bg == esc {
		return ""
	}
	s.bg = esc
	return esc
}

func (s *parserState) setAttr(attr int8) string {

	output := ""

	if attr < 0 {
		output = resetAll + s.fg + s.bg
	}

	s.attrs = attrs(uint8(s.attrs) + uint8(attr))

	for attr, esc := range attrMap {
		if uint8(s.attrs)&attr > 0 {
			output += esc
		}
	}

	return output
}

// NewParser creates a new parser that writes to w
func NewParser(w io.Writer) *Parser {
	return &Parser{
		writer:                w,
		IncludeLeadingResets:  true,
		IncludeTrailingResets: true,
	}
}

func (p *Parser) handleTag(name string) bool {

	if strings.HasPrefix(name, "/") {
		name = name[1:]
		if _, isFg := fgTags[name]; isFg {
			p.writer.Write([]byte(p.state.setFg(resetFg)))
			return true
		} else if _, isBg := bgTags[name]; isBg {
			p.writer.Write([]byte(p.state.setBg(resetBg)))
			return true
		} else if attr, isAttr := attrTags[name]; isAttr {
			p.writer.Write([]byte(p.state.setAttr(-int8(attr))))
			return true
		}
		return false
	}

	if esc, ok := fgTags[name]; ok {
		p.writer.Write([]byte(p.state.setFg(esc)))
		return true
	}

	if esc, ok := bgTags[name]; ok {
		p.writer.Write([]byte(p.state.setBg(esc)))
		return true
	}

	if attr, ok := attrTags[name]; ok {
		p.writer.Write([]byte(p.state.setAttr(int8(attr))))
		return true
	}

	return false
}

// Parse takes input from the reader and converts any provided tags to the relevant ANSI escape codes for output to parser's writer.
func (p *Parser) Parse(reader io.Reader) error {

	buffer := make([]byte, 1024)

	if p.IncludeLeadingResets {
		if _, err := p.writer.Write([]byte(resetAll)); err != nil {
			return err
		}
	}

	var inTag bool
	var tagName string

	for {
		n, err := reader.Read(buffer)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		for _, r := range []rune(string(buffer[:n])) {

			if inTag {
				if r == '>' {
					if !p.handleTag(tagName) {
						p.writer.Write([]byte(fmt.Sprintf("<%s>", tagName)))
					}
					tagName = ""
					inTag = false
					continue
				}
				tagName = fmt.Sprintf("%s%c", tagName, r)
				continue
			}

			if r == '<' {
				inTag = true
				continue
			}

			p.writer.Write([]byte(string([]rune{r})))
		}
	}

	if p.IncludeTrailingResets {
		p.writer.Write([]byte(resetAll))
	}

	return nil
}
