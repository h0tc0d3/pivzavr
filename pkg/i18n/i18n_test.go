package i18n

import (
	"bytes"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/language"
)

// useLanguage selects a language for the duration of a test and restores the
// language the tests started with, because the language of the package is
// global.
func useLanguage(t *testing.T, tag language.Tag) {
	t.Helper()
	previous := Language()
	t.Cleanup(func() { SetLanguage(previous) })
	SetLanguage(tag)
}

func TestLanguageIsEnglishByDefault(t *testing.T) {
	assert.Equal(t, language.English, Language())
	assert.Equal(t, "make a signature", Sprintf("make a signature"))
}

func TestSetLanguageTranslates(t *testing.T) {
	useLanguage(t, language.Russian)

	assert.Equal(t, language.Russian, Language())
	assert.Equal(t, "создать подпись", Sprintf("make a signature"))
	assert.Equal(t, "Не удалось открыть смарт-карту", Sprintf("Failed to open smart card"))
}

func TestSprintfFormatsTheTranslation(t *testing.T) {
	useLanguage(t, language.Russian)

	// The arguments are formatted into the translated message.
	assert.Equal(t,
		"Новый CHUID записан на смарт-карту.\nCHUID: 3019ABCD\n",
		Sprintf("New %s written to the smart card.\n%s: %s\n", "CHUID", "CHUID", "3019ABCD"))

	// A message that carries tabs and line breaks keeps them in the
	// translation.
	assert.Equal(t,
		"Сброс завершён. Все данные PIV стёрты со смарт-карты.\n"+
			"Теперь на смарт-карте действуют стандартные PIN, PUK и ключ управления:\n"+
			"\tPIN:\t12345678\n\tPUK:\t12345678\n\tКлюч управления:\t0102030405060708\n",
		Sprintf(
			"Reset complete. All PIV data has been cleared from the smart card.\n"+
				"The smart card now has the default PIN, PUK and management key:\n"+
				"\tPIN:\t%s\n\tPUK:\t%s\n\tManagement Key:\t%s\n",
			"12345678", "12345678", "0102030405060708"))
}

func TestArgumentsAreFormatted(t *testing.T) {
	useLanguage(t, language.Russian)

	// A verb that the catalog passes to the renderer of the message, such as
	// the type verb, is formatted the way fmt formats it, also for a message
	// that has no translation.
	assert.Equal(t, "Неподдерживаемый тип ключа struct {}.", Sprintf("Unsupported key type %T.", struct{}{}))
	assert.Equal(t, "hex: 800, type: struct {}.", Sprintf("hex: %x, type: %T.", 2048, struct{}{}))
}

func TestUnknownMessageIsPrintedUnchanged(t *testing.T) {
	useLanguage(t, language.Russian)

	// A message without a translation falls back to its English text, and its
	// arguments are still formatted.
	assert.Equal(t, "not translated", Sprintf("not translated"))
	assert.Equal(t, "not translated: 7", Sprintf("not translated: %d", 7))
}

func TestFprintf(t *testing.T) {
	useLanguage(t, language.Russian)

	var buf bytes.Buffer
	n, err := Fprintf(&buf, "New PIN set.\n")
	require.NoError(t, err)
	assert.Equal(t, "Новый PIN установлен.\n", buf.String())
	assert.Equal(t, buf.Len(), n)
}

func TestErrorHelpersTranslate(t *testing.T) {
	useLanguage(t, language.Russian)

	assert.EqualError(t, New("Read message file"), "Чтение файла сообщения")
	assert.EqualError(t, Errorf("Invalid --protect value %q, use 0 or 1.", "2"), "Неверное значение --protect \"2\", используйте 0 или 1.")

	cause := errors.New("cause")
	wrapped := Wrap(cause, "Read signature file")
	assert.EqualError(t, wrapped, "Чтение файла подписи: cause")
	assert.Equal(t, cause, errors.Cause(wrapped))

	assert.EqualError(t, Wrapf(cause, "expected 0 or 1 file arguments but got: %v", []string{"a", "b"}),
		"ожидалось 0 или 1 аргументов-файлов, но получено: [a b]: cause")
}

func TestResolveLanguageFromConfiguration(t *testing.T) {
	// The tests control the locale so that a configured language is the only
	// thing that selects what the result is compared against.
	t.Setenv("LC_ALL", "")
	t.Setenv("LC_MESSAGES", "")
	t.Setenv("LANG", "")

	testCases := []struct {
		name       string
		configured string
		want       language.Tag
	}{
		{name: "an empty setting falls back to the locale", configured: "", want: language.English},
		{name: "a language name", configured: "ru", want: language.Russian},
		{name: "a locale name", configured: "ru_RU", want: language.Russian},
		{name: "a locale with an encoding", configured: "ru_RU.UTF-8", want: language.Russian},
		{name: "a locale with a modifier", configured: "ru_RU.UTF-8@euro", want: language.Russian},
		{name: "a region subtag", configured: "ru-RU", want: language.Russian},
		{name: "a padded setting", configured: "  ru  ", want: language.Russian},
		{name: "English", configured: "en", want: language.English},
		{name: "the POSIX locale", configured: "C", want: language.English},
		{name: "a language without a translation", configured: "fr", want: language.English},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ResolveLanguage(tc.configured))
		})
	}
}

func TestResolveLanguageUsesTheLocaleWithoutAConfiguration(t *testing.T) {
	t.Setenv("LC_ALL", "ru_RU.UTF-8")
	assert.Equal(t, language.Russian, ResolveLanguage(""))
}

func TestDetectLanguage(t *testing.T) {
	testCases := []struct {
		name string
		lc   string
		lang string
		want language.Tag
	}{
		{name: "no locale at all", want: language.English},
		{name: "the POSIX locale", lang: "C", want: language.English},
		{name: "Russian with an encoding", lang: "ru_RU.UTF-8", want: language.Russian},
		{name: "a bare language", lang: "ru", want: language.Russian},
		{name: "a locale that is not translated", lang: "fr_FR.UTF-8", want: language.English},
		{name: "a malformed locale", lang: "!!", want: language.English},
		{name: "LC_ALL wins over LANG", lc: "ru_RU.UTF-8", lang: "en_US.UTF-8", want: language.Russian},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("LC_ALL", tc.lc)
			t.Setenv("LC_MESSAGES", "")
			t.Setenv("LANG", tc.lang)
			assert.Equal(t, tc.want, DetectLanguage())
		})
	}
}
