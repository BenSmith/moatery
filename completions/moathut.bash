# bash completion for moathut, installed as
# /usr/share/bash-completion/completions/moathut

# Where moathut keeps huts and credentials: XDG_CONFIG_HOME when it is
# absolute, as paths.user_dirs reads it, else ~/.config.
_moathut_config() {
    if [[ $XDG_CONFIG_HOME == /* ]]; then
        printf '%s\n' "$XDG_CONFIG_HOME/moatery"
    else
        printf '%s\n' "$HOME/.config/moatery"
    fi
}

_moathut_huts() {
    local f root
    root=$(_moathut_config)
    for f in "$root"/hut/*/hut.json; do
        [[ -f $f ]] || continue
        f=${f%/hut.json}
        printf '%s\n' "${f##*/}"
    done
}

_moathut_credentials() {
    local f root
    root=$(_moathut_config)
    for f in "$root"/credentials/*.json; do
        [[ -f $f ]] || continue
        f=${f%.json}
        printf '%s\n' "${f##*/}"
    done
}

_moathut_takes_value() {
    case $1 in
        --network-policy | --image | --mount | --seccomp | --like | \
            --method | --path | --host | --env | --auth-header | \
            --auth-format)
            return 0 ;;
    esac
    return 1
}

_moathut() {
    local cur prev words cword split
    _init_completion -s || return

    # The words so far that are not options or their values. After `--`
    # come the hut's command and its words, which are not moathut's.
    local i pos=()
    for ((i = 1; i < cword; i++)); do
        case ${words[i]} in
            --) return ;;
            -*)
                if _moathut_takes_value "${words[i]}"; then
                    ((i++))
                    [[ ${words[i]} == = ]] && ((i++))
                fi ;;
            *) pos+=("${words[i]}") ;;
        esac
    done

    case $prev in
        --network-policy) _filedir; return ;;
        --mount) _filedir -d; return ;;
        --seccomp)
            _filedir
            COMPREPLY+=($(compgen -W "strict debug" -- "$cur"))
            return ;;
        --like)
            COMPREPLY=($(compgen -W "$(_moathut_huts)" -- "$cur"))
            return ;;
        --method)
            COMPREPLY=($(compgen -W "GET HEAD POST PUT PATCH DELETE
                OPTIONS" -- "$cur"))
            return ;;
        --image | --path | --host | --env | --auth-header | --auth-format)
            return ;;
    esac

    local command=${pos[0]} n=$((${#pos[@]} - 1)) options="" names=""
    case $command in
        "")
            options="--version"
            names="create enter log allow network-policy stop rm ls
                credential ptyxis" ;;
        create)
            options="--network-policy --image --mount --autostart --seccomp
                --like --dry-run" ;;
        enter)
            options="--root"
            ((n == 0)) && names=$(_moathut_huts) ;;
        log)
            options="--refused"
            ((n == 0)) && names=$(_moathut_huts) ;;
        allow)
            options="--method --path"
            ((n == 0)) && names=$(_moathut_huts) ;;
        network-policy | stop)
            ((n == 0)) && names=$(_moathut_huts) ;;
        rm)
            options="--home"
            ((n == 0)) && names=$(_moathut_huts) ;;
        ptyxis)
            options="--remove"
            ((n == 0)) && names=$(_moathut_huts) ;;
        credential)
            case ${pos[1]} in
                "") names="add ls rm" ;;
                add)
                    options="--host --env --auth-header --auth-format"
                    ((n == 1)) && names=$(_moathut_credentials) ;;
                rm) ((n == 1)) && names=$(_moathut_credentials) ;;
            esac ;;
    esac

    if [[ $cur == -* ]]; then
        COMPREPLY=($(compgen -W "$options --help" -- "$cur"))
    else
        COMPREPLY=($(compgen -W "$names" -- "$cur"))
    fi
} && complete -F _moathut moathut
