# fish completion for pivzavr.
#
# Install this file as
#   ~/.config/fish/completions/pivzavr.fish
# or as /usr/share/fish/vendor_completions.d/pivzavr.fish.

set -l slots 9a 9b 9c 9d 9e 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 f9
set -l extensions sig sign sgn p7s p7m asc pem
set -l algorithms AES128 AES192 AES256

complete -c pivzavr -s h -l help -d 'Print the help message'
complete -c pivzavr -s V -l version -d 'Print the version of pivzavr and exit'
complete -c pivzavr -s s -l sign -d 'Make a signature'
complete -c pivzavr -l verify -d 'Verify a signature'
complete -c pivzavr -l reset -d 'Restore the factory state of the smart card'
complete -c pivzavr -l unlock -d 'Unlock the smart card PIN with the PUK'
complete -c pivzavr -l set-pin -d 'Replace the smart card PIN'
complete -c pivzavr -l set-puk -d 'Replace the smart card PUK'
complete -c pivzavr -l set-chuid -d 'Write a new Card Holder Unique Identifier'
complete -c pivzavr -l set-ccc -d 'Write a new Card Capability Container'
complete -c pivzavr -l set-management-key -x -a "$algorithms" -d 'Replace the card management key'
complete -c pivzavr -l protect -x -a '0 1' -d 'Store the new management key on the smart card'
complete -c pivzavr -l random -d 'Generate the new card management key'
complete -c pivzavr -s w -l slot -x -a "$slots" -d 'Choose a PIV slot by key reference'
complete -c pivzavr -s p -l print -d 'Print the certificate with its fingerprint and details'
complete -c pivzavr -s i -l info -d 'Print device information and active PIV slots'
complete -c pivzavr -l update-trust -d 'Rebuild the trust store'
complete -c pivzavr -s u -l local-user -x -a '(__fish_complete_users)' -d 'Use USER-ID to sign'
complete -c pivzavr -s b -l detach-sign -d 'Make a detached signature'
complete -c pivzavr -s a -l armor -d 'Create ascii armored output'
complete -c pivzavr -l clearsign -d 'Make a clear text signature of a text file'
complete -c pivzavr -s o -l output -r -d 'Write the signature to FILE'
complete -c pivzavr -l ext -x -a "$extensions" -d 'Extension of the signature file'
complete -c pivzavr -l status-fd -x -a '1 2' -d 'Write special status strings to the file descriptor n'
complete -c pivzavr -s t -l timestamp-authority -r -d 'URL of an RFC 3161 timestamp authority'
complete -c pivzavr -f -a '(__fish_complete_path)'
