// Package i18n translates the messages that pivzavr prints into the language of
// the user.
//
// The English text of a message is the key under which its translation is looked
// up, so a message that has no translation yet is printed in English unchanged.
// The package offers the formatting and error helpers that the rest of the
// program uses in place of fmt and github.com/pkg/errors, so that a message is
// translated wherever it is composed. The helpers mirror the functions they
// replace:
//
//	i18n.Sprintf, i18n.Fprintf   for fmt.Sprintf, fmt.Fprintf
//	i18n.New, i18n.Errorf        for errors.New, errors.Errorf
//	i18n.Wrap, i18n.Wrapf        for errors.Wrap, errors.Wrapf
//
// A message error that is a package level value is created before the language
// of the program is known, so it is made with i18n.Message, which translates the
// message when the error is reported rather than when it is created.
//
// Only the format string is translated: the arguments are formatted with the
// rules of the selected language, as golang.org/x/text/message does.
//
// The language is English until SetLanguage is called. ResolveLanguage returns
// the language to use from the "language" setting of the configuration file, or
// the locale of the system when the setting is not given.
package i18n

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
	"golang.org/x/text/message/catalog"
)

// supported are the languages pivzavr is translated into. English is the source
// language of the messages and the fallback, so a message whose translation is
// missing is printed in English; a locale that names any other language selects
// English as well.
var supported = []language.Tag{
	language.English,
	language.Russian,
}

// cat holds the translations. Only a language other than English is registered:
// the key of a message is its English text, which the printer returns unchanged
// for English, so the English messages need no entry.
var cat = catalog.NewBuilder(catalog.Fallback(language.English))

func init() {
	for key, translation := range russian {
		if err := cat.SetString(language.Russian, key, translation); err != nil {
			// The translations are part of the program, so a translation that
			// the catalog rejects is a mistake in this package rather than in
			// the input of the program, and it is reported instead of being
			// silently dropped.
			panic(fmt.Sprintf("i18n: Russian translation of %q: %v", key, err))
		}
	}
}

// localeEnv are the environment variables that name the locale of the user, in
// the order they take precedence.
var localeEnv = []string{"LC_ALL", "LC_MESSAGES", "LANG"}

var (
	mu       sync.RWMutex
	current  = language.English
	printers = map[language.Tag]*message.Printer{}
)

// SetLanguage sets the language that messages are translated into. The language
// is English until this is called.
func SetLanguage(t language.Tag) {
	mu.Lock()
	defer mu.Unlock()
	current = t
}

// Language returns the language that messages are translated into.
func Language() language.Tag {
	mu.RLock()
	defer mu.RUnlock()
	return current
}

// DetectLanguage returns the language of the locale of the system, or English
// when no locale names a language or the locale names none that pivzavr is
// translated into. The locale is taken from LC_ALL, LC_MESSAGES or LANG, in
// that order, and may carry a character encoding and a modifier, as in
// "ru_RU.UTF-8@euro".
func DetectLanguage() language.Tag {
	for _, name := range localeEnv {
		locale := strings.TrimSpace(os.Getenv(name))
		if locale == "" {
			continue
		}
		if tag, ok := parseLocale(locale); ok {
			return tag
		}
	}
	return language.English
}

// ResolveLanguage returns the language to translate into: the language named by
// configured, which is the "language" setting of the configuration file, or the
// language of the system locale when configured is empty. A configured language
// that pivzavr is not translated into selects English, and one that names no
// language at all selects the language of the system locale.
func ResolveLanguage(configured string) language.Tag {
	configured = strings.TrimSpace(configured)
	if configured == "" {
		return DetectLanguage()
	}
	if tag, ok := parseLocale(configured); ok {
		return tag
	}
	return DetectLanguage()
}

// parseLocale parses a locale or a language name into one of the supported
// languages. The boolean result reports whether the value named a language: a
// value that names none, such as an empty or a malformed tag, does not, while
// the POSIX locale does and names English.
func parseLocale(locale string) (language.Tag, bool) {
	// Strip the character encoding and the modifier of a POSIX locale:
	// "ru_RU.UTF-8@euro" names Russian.
	if i := strings.IndexAny(locale, ".@"); i >= 0 {
		locale = locale[:i]
	}
	// The POSIX locale names the default language, which is English here.
	switch locale {
	case "", "C", "POSIX":
		return language.English, true
	}

	tag, err := language.Parse(strings.ReplaceAll(locale, "_", "-"))
	if err != nil {
		return language.Und, false
	}
	return matchLanguage(tag), true
}

// matchLanguage returns the supported language that tag names, or English when
// tag names a language that pivzavr is not translated into. The script, the
// region and any modifier of the tag are ignored, because they do not change
// the translation.
func matchLanguage(tag language.Tag) language.Tag {
	base, _ := tag.Base()
	for _, languageTag := range supported {
		if supportedBase, _ := languageTag.Base(); supportedBase == base {
			return languageTag
		}
	}
	return language.English
}

// printer returns the message printer for the current language. The printers
// are cached, because one is needed for every message and a printer carries the
// number formats of its language.
func printer() *message.Printer {
	mu.RLock()
	tag := current
	p := printers[tag]
	mu.RUnlock()
	if p != nil {
		return p
	}

	mu.Lock()
	defer mu.Unlock()
	if p = printers[tag]; p != nil {
		return p
	}
	p = message.NewPrinter(tag, message.Catalog(cat))
	printers[tag] = p
	return p
}

// Sprintf translates and formats a message like fmt.Sprintf.
func Sprintf(format string, args ...interface{}) string {
	return printer().Sprintf(format, args...)
}

// Fprintf translates and writes a message like fmt.Fprintf.
func Fprintf(w io.Writer, format string, args ...interface{}) (int, error) {
	return printer().Fprintf(w, format, args...)
}

// New returns an error with a translated message like errors.New.
func New(message string) error {
	return errors.New(Sprintf(message))
}

// Errorf returns an error with a translated message like errors.Errorf.
func Errorf(format string, args ...interface{}) error {
	return errors.New(Sprintf(format, args...))
}

// Wrap annotates err with a translated message like errors.Wrap.
func Wrap(err error, message string) error {
	return errors.Wrap(err, Sprintf(message))
}

// Wrapf annotates err with a translated message like errors.Wrapf.
func Wrapf(err error, format string, args ...interface{}) error {
	return errors.Wrap(err, Sprintf(format, args...))
}

// MessageError is an error whose message is translated when the error is
// reported rather than when it is created. It allows a message error to be a
// package level value, which is created before the language of the program is
// known.
type MessageError string

// Error returns the translated message.
func (e MessageError) Error() string {
	return Sprintf(string(e))
}

// Message returns an error with a translated message like New, but translates
// the message when the error is reported instead of when it is created. It is
// meant for a message error that is a package level value.
func Message(message string) error {
	return MessageError(message)
}
