# pwgen

Small command line password generator written in C. Randomness comes from `/dev/urandom`, and characters are picked with rejection sampling so there is no modulo bias.

Works on Linux, macOS, BSD and WSL.

## Build

```bash
make
# or without make:
gcc -O2 -Wall -Wextra -o pwgen pwgen.c -lm
```

Optional install:

```bash
sudo make install      # puts it in /usr/local/bin
make clean
```

## Usage

```
pwgen [options]
```

| Option | Description |
|---|---|
| `-l, --length N` | password length (default 16) |
| `-n, --count N` | number of passwords (default 1) |
| `-o, --output FILE` | append to FILE (mode 600) instead of printing |
| `-q, --quiet` | only print passwords, no entropy info |
| `-L / -U / -D / -S` | disable lowercase / uppercase / digits / symbols |
| `-y, --symbols SET` | custom symbol set |
| `-x, --exclude CHARS` | never use these characters |
| `-a, --no-ambiguous` | skip look-alike chars (`0 O 1 l I \|`) |
| `-r, --no-repeat` | no character appears twice |
| `--min-lower/upper/digits/symbols N` | minimum count per class |
| `--pin` | digits only |
| `--hex` | hex string |
| `-w, --words N` | passphrase with N words |
| `-f, --wordlist FILE` | wordlist, one word per line (EFF diceware format works) |
| `-d, --delimiter STR` | word separator (default `-`) |
| `-C, --capitalize` | capitalize each word |
| `-h, --help` / `-V, --version` | help / version |

Entropy info goes to stderr, so piping the passwords is safe.

## Examples

```bash
./pwgen
./pwgen -l 24 -n 5 --min-digits 3 --min-symbols 2
./pwgen -l 20 -a -x '{}[]' -y '!@#_'
./pwgen --pin -l 6
./pwgen -w 5 -f eff_large_wordlist.txt -C -d .
./pwgen -l 32 -q | xclip -selection clipboard
```

## Notes

- Entropy is an estimate: `length * log2(pool size)`. Minimums and `--no-repeat` lower it slightly.
- Passphrase entropy assumes the wordlist has no duplicate words.
- Don't generate passwords on a machine you don't trust.

## License

MIT
