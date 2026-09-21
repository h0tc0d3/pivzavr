# bash completion for pivzavr                                  -*- shell-script -*-
#
# Install this file as
#   $BASH_COMPLETION_USER_DIR/completions/pivzavr
# or as /usr/share/bash-completion/completions/pivzavr, or source it from
# ~/.bashrc.

_pivzavr_slots="9a 9b 9c 9d 9e 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f 90 91 92 93 94 95 f9"

_pivzavr_options="--help --version --sign --verify --reset --unlock --set-pin
--set-puk --set-chuid --set-ccc --set-management-key --protect --random --slot
--print --info --update-trust --local-user --detach-sign --armor --clearsign
--output --ext --status-fd --timestamp-authority"

_pivzavr() {
    local cur prev

    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    case "${prev}" in
        --slot|-w)
            COMPREPLY=( $(compgen -W "${_pivzavr_slots}" -- "${cur}") )
            return 0
            ;;
        --ext)
            COMPREPLY=( $(compgen -W "sig sign sgn p7s p7m asc pem" -- "${cur}") )
            return 0
            ;;
        --set-management-key)
            COMPREPLY=( $(compgen -W "AES128 AES192 AES256" -- "${cur}") )
            return 0
            ;;
        --protect)
            COMPREPLY=( $(compgen -W "0 1" -- "${cur}") )
            return 0
            ;;
        --output|-o|--local-user|-u|--timestamp-authority|-t)
            COMPREPLY=( $(compgen -f -- "${cur}") )
            return 0
            ;;
        --status-fd)
            COMPREPLY=( $(compgen -W "1 2" -- "${cur}") )
            return 0
            ;;
    esac

    if [[ "${cur}" == -* ]]; then
        COMPREPLY=( $(compgen -W "${_pivzavr_options}" -- "${cur}") )
        return 0
    fi

    COMPREPLY=( $(compgen -f -- "${cur}") )
    return 0
}

complete -o filenames -F _pivzavr pivzavr
