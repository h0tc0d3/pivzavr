package main

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/h0tc0d3/pivzavr/pkg/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/language"
)

func TestOrderUsageMovesAdminOptionsBehindReset(t *testing.T) {
	// The usage line names --unlock too, which must not be mistaken for the
	// option entry.
	usage := "Usage: pivzavr [-r] [--unlock] [files]\n" +
		" -h, --help    print this help message\n" +
		"     --reset   restore the factory state of the smart card\n" +
		" -s, --sign    make a signature\n" +
		"     --random  generate the new card management key\n" +
		"     --set-pin  replace the smart card PIN\n" +
		"     --unlock  unlock the smart card PIN with the PUK\n" +
		"     --verify  verify a signature\n"

	var names []string
	for _, block := range orderUsage(usageBlocks(usage)) {
		names = append(names, optionName(block))
	}

	// The administration options follow --reset in the order they are listed
	// in, whatever order getopt printed them in.
	assert.Equal(t, []string{
		"",
		"-h, --help",
		"--reset",
		"--unlock",
		"--set-pin",
		"--random",
		"-s, --sign",
		"--verify",
	}, names)
}

func TestOrderUsageWithoutAdminOptions(t *testing.T) {
	usage := "Usage: pivzavr [files]\n" +
		" -h, --help  print this help message\n" +
		" -s, --sign  make a signature\n"

	var names []string
	for _, block := range orderUsage(usageBlocks(usage)) {
		names = append(names, optionName(block))
	}
	assert.Equal(t, []string{"", "-h, --help", "-s, --sign"}, names)
}

func TestUsageBlocksKeepsWrappedHelpWithOption(t *testing.T) {
	usage := "Usage: pivzavr [files]\n" +
		"     --reset   restore the factory state of the smart\n" +
		"               card by erasing the PIV keys and\n" +
		"               certificates\n" +
		"     --unlock  unlock the smart card PIN with the PUK,\n" +
		"               resetting the PIN and PUK retry counters\n"

	blocks := usageBlocks(usage)
	require.Len(t, blocks, 3)
	assert.Equal(t, "--reset", optionName(blocks[1]))
	assert.Len(t, blocks[1], 3)
	assert.Equal(t, "--unlock", optionName(blocks[2]))
	assert.Len(t, blocks[2], 2)
}

func TestUsageLineWithoutAdmin(t *testing.T) {
	usage := "Usage: pivzavr [-abhiprs] [--reset] [-u USER-ID] [--protect 0|1] [--random] [--set-management-key ALGO] [--unlock] [--update-trust] [--verify] [files]\n" +
		" -h, --help  print this help message\n"

	// Only the usage line changes, and the options that are kept keep their
	// own brackets.
	assert.Equal(t,
		"Usage: pivzavr [-abhiprs] [-u USER-ID] [--verify] [files]\n"+
			" -h, --help  print this help message\n",
		usageLineWithoutAdmin(usage))
}

func TestUsageLineWithoutAdmin_lastOption(t *testing.T) {
	assert.Equal(t, "Usage: pivzavr [files]", usageLineWithoutAdmin("Usage: pivzavr [--unlock] [files]"))
	assert.Equal(t, "Usage: pivzavr", usageLineWithoutAdmin("Usage: pivzavr [--set-pin]"))
	assert.Equal(t, "Usage: pivzavr", usageLineWithoutAdmin("Usage: pivzavr [--set-management-key ALGO]"))
}

func TestOptionNames(t *testing.T) {
	// A parameter is written behind an equals sign, which is not part of the
	// option name.
	assert.True(t, optionNames([]string{"     --protect=0|1       store the key\n"}, "--protect"))
	assert.True(t, optionNames([]string{"     --set-pin  replace the PIN\n"}, "--set-pin"))
	// An optional parameter is bracketed in the option list.
	assert.True(t, optionNames([]string{"     --set-management-key[=ALGO]  replace the key\n"}, "--set-management-key"))
	assert.False(t, optionNames([]string{"     --set-puk  replace the PUK\n"}, "--set-pin"))
	assert.False(t, optionNames([]string{" -s, --sign  make a signature\n"}, "--set-pin"))
}

func TestManagementKeyArgument(t *testing.T) {
	// A command that does not replace the management key keeps its arguments,
	// such as the file that is signed.
	algorithm, args, err := managementKeyArgument(false, "", []string{"message.pem"})
	require.NoError(t, err)
	assert.Empty(t, algorithm)
	assert.Equal(t, []string{"message.pem"}, args)

	// getopt only takes the value of an option with an optional parameter when
	// it is attached with an equals sign, so an algorithm that is written
	// behind the option is read from the arguments that follow it.
	algorithm, args, err = managementKeyArgument(true, "", []string{"AES128"})
	require.NoError(t, err)
	assert.Equal(t, "AES128", algorithm)
	assert.Empty(t, args)

	// An algorithm that is attached is kept, and no argument follows it.
	algorithm, args, err = managementKeyArgument(true, "AES256", nil)
	require.NoError(t, err)
	assert.Equal(t, "AES256", algorithm)
	assert.Empty(t, args)

	// An option without an algorithm selects the default.
	algorithm, args, err = managementKeyArgument(true, "", nil)
	require.NoError(t, err)
	assert.Empty(t, algorithm)
	assert.Empty(t, args)

	// Files are not part of the command.
	_, _, err = managementKeyArgument(true, "AES256", []string{"message.pem"})
	assert.ErrorContains(t, err, "--set-management-key")
	_, _, err = managementKeyArgument(true, "", []string{"AES128", "message.pem"})
	assert.ErrorContains(t, err, "--set-management-key")
}

func TestParseProtect(t *testing.T) {
	testCases := []struct {
		value   string
		want    bool
		wantErr bool
	}{
		{value: "", want: false},
		{value: "0", want: false},
		{value: "1", want: true},
		{value: " 1 ", want: true},
		{value: "2", wantErr: true},
		{value: "no", wantErr: true},
	}
	for _, tc := range testCases {
		t.Run(tc.value, func(t *testing.T) {
			got, err := parseProtect(tc.value)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestManagementKeyMessage(t *testing.T) {
	assert.Contains(t, managementKeyMessage(true), "protected by the PIN")
	assert.Equal(t, "New management key set.\n", managementKeyMessage(false))
}

func TestObjectMessage(t *testing.T) {
	message := objectMessage("CHUID", []byte{0x30, 0x19, 0xAB, 0xCD})
	assert.Equal(t, "New CHUID written to the smart card.\nCHUID: 3019ABCD\n", message)
}

func TestCommandError(t *testing.T) {
	// Exactly one command is the only valid count; a call that names none or
	// several is rejected with the message that describes the problem.
	require.NoError(t, commandError(1))
	assert.EqualError(t, commandError(0), commandList)
	assert.EqualError(t, commandError(2), multipleCommands)
	assert.EqualError(t, commandError(3), multipleCommands)
}

func TestMessagesAreTranslated(t *testing.T) {
	// The language is resolved from the configuration file by runCommand, so
	// the tests select the language the messages are reported in directly.
	t.Cleanup(func() { i18n.SetLanguage(language.English) })
	i18n.SetLanguage(language.Russian)

	assert.Equal(t, "Новый ключ управления установлен.\n", managementKeyMessage(false))
	assert.Contains(t, managementKeyMessage(true), "под защитой PIN")
	assert.Equal(t,
		"Новый CHUID записан на смарт-карту.\nCHUID: 3019ABCD\n",
		objectMessage("CHUID", []byte{0x30, 0x19, 0xAB, 0xCD}))
	assert.Contains(t, resetMessage(), "Сброс завершён")

	assert.EqualError(t, commandError(0), i18n.Sprintf(commandList))
	assert.EqualError(t, commandError(2), i18n.Sprintf(multipleCommands))
	assert.EqualError(t, clearsignOptionError("sig", false), "Параметр Ext нельзя указывать с --clearsign.")
	_, _, err := managementKeyArgument(true, "AES256", []string{"message.pem"})
	assert.EqualError(t, err, "С --set-management-key нельзя указывать файлы.")
}

func TestClearsignOptionError(t *testing.T) {
	// A clear text signature accepts neither a signature extension nor
	// --detach-sign, and an invocation that names neither is accepted.
	require.NoError(t, clearsignOptionError("", false))
	assert.EqualError(t, clearsignOptionError("sig", false), "Ext cannot be specified with --clearsign.")
	assert.EqualError(t, clearsignOptionError("", true), "Detach-sign cannot be specified with --clearsign.")
	assert.EqualError(t, clearsignOptionError("sig", true), "Ext cannot be specified with --clearsign.")
}

func TestOrderUsageKeepsUpdateTrust(t *testing.T) {
	// Updating the trust store does not touch a smart card, so the option is
	// not moved behind --reset.
	usage := "Usage: pivzavr [files]\n" +
		" -h, --help        print this help message\n" +
		"     --update-trust  rebuild the trust store\n" +
		"     --reset       restore the factory state of the smart card\n" +
		"     --unlock      unlock the smart card PIN with the PUK\n"

	var names []string
	for _, block := range orderUsage(usageBlocks(usage)) {
		names = append(names, optionName(block))
	}

	assert.Equal(t, []string{"", "-h, --help", "--update-trust", "--reset", "--unlock"}, names)
}

func TestWrap(t *testing.T) {
	// A description shorter than the width is returned unchanged.
	assert.Equal(t, "make a signature", wrap("make a signature", 60))

	// An English description is wrapped at word boundaries, so that no line is
	// wider than 60 characters.
	english := wrap("restore the factory state of the smart card by erasing the PIV keys and certificates", 60)
	assert.Equal(t,
		"restore the factory state of the smart card by erasing the\n"+
			"PIV keys and certificates",
		english)
	for _, line := range strings.Split(english, "\n") {
		assert.LessOrEqual(t, utf8.RuneCountInString(line), 60)
	}

	// A Russian description is wrapped after the same number of characters, not
	// after a smaller number of bytes.
	russian := wrap("восстановить заводское состояние смарт-карты, стерев ключи и сертификаты PIV", 60)
	assert.Equal(t,
		"восстановить заводское состояние смарт-карты, стерев ключи и\n"+
			"сертификаты PIV",
		russian)
	for _, line := range strings.Split(russian, "\n") {
		assert.LessOrEqual(t, utf8.RuneCountInString(line), 60)
	}
}
