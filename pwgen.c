/*
 * pwgen - small command line password generator
 *
 * Randomness comes straight from /dev/urandom (Linux / macOS / BSD / WSL).
 * Picking a char uses rejection sampling so there's no modulo bias.
 *
 * Build:  make        (or: gcc -O2 -Wall -Wextra -o pwgen pwgen.c -lm)
 */
#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <math.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define VERSION    "1.0"
#define MAX_LEN    1024
#define MAX_COUNT  10000
#define MAX_WORDS  200000

static const char LOWER[]     = "abcdefghijklmnopqrstuvwxyz";
static const char UPPER[]     = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const char DIGITS[]    = "0123456789";
static const char HEXCHARS[]  = "0123456789abcdef";
static const char SYMBOLS[]   = "!@#$%^&*()-_=+[]{};:,.<>?/";
static const char AMBIGUOUS[] = "0O1lI|";

typedef enum { MODE_PASSWORD, MODE_PIN, MODE_HEX, MODE_PHRASE } Mode;

typedef struct {
    Mode mode;
    int length, count;
    int use_lower, use_upper, use_digits, use_symbols;
    int min_lower, min_upper, min_digits, min_symbols;
    int no_ambiguous, no_repeat;
    int words, capitalize, quiet;
    const char *symbols, *exclude, *wordlist, *delim, *outfile;
} Config;

typedef struct {
    char c[256];
    size_t n;
} Pool;

/* long-only options need ids outside the char range */
enum {
    OPT_MIN_LOWER = 256, OPT_MIN_UPPER, OPT_MIN_DIGITS, OPT_MIN_SYMBOLS,
    OPT_PIN, OPT_HEX
};

static void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "pwgen: ");
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    va_end(ap);
    exit(1);
}

/* ---------- randomness ---------- */

static FILE *urandom;

static uint32_t rnd32(void)
{
    uint32_t v;
    if (fread(&v, sizeof v, 1, urandom) != 1) {
        perror("pwgen: reading /dev/urandom");
        exit(2);
    }
    return v;
}

/* uniform number in [0, n) */
static uint32_t rnd_below(uint32_t n)
{
    uint32_t limit = (UINT32_MAX / n) * n;
    uint32_t v;
    do {
        v = rnd32();
    } while (v >= limit);
    return v % n;
}

/* ---------- character pools ---------- */

static void pool_build(Pool *p, const char *src, const Config *cfg, int sym_pool)
{
    p->n = 0;
    for (; *src; src++) {
        unsigned char ch = (unsigned char)*src;
        if (ch < 33 || ch > 126)
            continue;
        if (sym_pool && isalnum(ch))   /* keep the symbol pool separate from letters/digits */
            continue;
        if (cfg->no_ambiguous && strchr(AMBIGUOUS, ch))
            continue;
        if (cfg->exclude && strchr(cfg->exclude, ch))
            continue;
        if (memchr(p->c, ch, p->n))     /* already in there */
            continue;
        if (p->n < sizeof p->c)
            p->c[p->n++] = (char)ch;
    }
}

static void pool_append(Pool *dst, const Pool *src)
{
    for (size_t i = 0; i < src->n && dst->n < sizeof dst->c; i++)
        dst->c[dst->n++] = src->c[i];
}

static char pick(const Pool *p, const char *used, size_t nused, int no_repeat)
{
    for (;;) {
        char ch = p->c[rnd_below((uint32_t)p->n)];
        if (!no_repeat || !memchr(used, ch, nused))
            return ch;
    }
}

/* ---------- generators ---------- */

static void gen_password(const Config *cfg, const Pool cls[4], const Pool *all, char *out)
{
    const int mins[4] = { cfg->min_lower, cfg->min_upper, cfg->min_digits, cfg->min_symbols };
    int len = cfg->length, pos = 0;

    /* satisfy the minimums first, then fill the rest from everything */
    for (int k = 0; k < 4; k++)
        for (int i = 0; i < mins[k]; i++, pos++)
            out[pos] = pick(&cls[k], out, pos, cfg->no_repeat);

    while (pos < len) {
        out[pos] = pick(all, out, pos, cfg->no_repeat);
        pos++;
    }

    /* Fisher-Yates, otherwise the required chars would always sit at the front */
    for (int i = len - 1; i > 0; i--) {
        int j = (int)rnd_below((uint32_t)i + 1);
        char t = out[i];
        out[i] = out[j];
        out[j] = t;
    }
    out[len] = '\0';
}

static char **load_words(const char *path, size_t *count)
{
    FILE *f = fopen(path, "r");
    if (!f)
        die("can't open wordlist '%s': %s", path, strerror(errno));

    char **list = NULL;
    size_t cap = 0, n = 0;
    char line[256];

    while (fgets(line, sizeof line, f) && n < MAX_WORDS) {
        /* EFF diceware lines look like "11111<tab>abacus", so take the last token */
        char *tok = NULL;
        for (char *t = strtok(line, " \t\r\n"); t; t = strtok(NULL, " \t\r\n"))
            tok = t;
        if (!tok || strlen(tok) < 2 || strlen(tok) > 24)
            continue;

        int ok = 1;
        for (char *p = tok; *p; p++)
            if (!isalpha((unsigned char)*p) && *p != '-')
                ok = 0;
        if (!ok)
            continue;

        if (n == cap) {
            cap = cap ? cap * 2 : 1024;
            char **tmp = realloc(list, cap * sizeof *list);
            if (!tmp)
                die("out of memory");
            list = tmp;
        }
        list[n++] = strdup(tok);
    }
    fclose(f);

    if (n < 2)
        die("wordlist '%s' has too few usable words", path);
    *count = n;
    return list;
}

static char *gen_phrase(const Config *cfg, char **words, size_t nwords)
{
    size_t dl = strlen(cfg->delim);
    char *out = malloc((size_t)cfg->words * (24 + dl + 1) + 1);
    if (!out)
        die("out of memory");
    out[0] = '\0';

    for (int i = 0; i < cfg->words; i++) {
        const char *w = words[rnd_below((uint32_t)nwords)];
        size_t at = strlen(out);
        strcpy(out + at, w);
        if (cfg->capitalize)
            out[at] = (char)toupper((unsigned char)out[at]);
        if (i < cfg->words - 1)
            strcat(out, cfg->delim);
    }
    return out;
}

/* ---------- misc helpers ---------- */

static const char *strength(double bits)
{
    if (bits < 40)  return "weak";
    if (bits < 60)  return "fair";
    if (bits < 80)  return "good";
    if (bits < 128) return "strong";
    return "very strong";
}

static int parse_int(const char *s, int lo, int hi, const char *name)
{
    char *end;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno || end == s || *end || v < lo || v > hi)
        die("%s must be a number between %d and %d", name, lo, hi);
    return (int)v;
}

static void wipe(void *p, size_t n)
{
    volatile unsigned char *v = p;
    while (n--)
        *v++ = 0;
}

static void usage(FILE *to)
{
    fputs(
"pwgen " VERSION " - command line password generator\n"
"\n"
"Usage: pwgen [options]\n"
"\n"
"General:\n"
"  -l, --length N        password length (default 16)\n"
"  -n, --count N         how many passwords to generate (default 1)\n"
"  -o, --output FILE     append results to FILE instead of printing (mode 600)\n"
"  -q, --quiet           print only the passwords, no entropy info\n"
"  -h, --help            show this help\n"
"  -V, --version         show version\n"
"\n"
"Character sets (all on by default):\n"
"  -L, --no-lower        no lowercase letters\n"
"  -U, --no-upper        no uppercase letters\n"
"  -D, --no-digits       no digits\n"
"  -S, --no-symbols      no symbols\n"
"  -y, --symbols SET     use your own symbol set, e.g. -y '!@#_'\n"
"  -x, --exclude CHARS   never use these characters\n"
"  -a, --no-ambiguous    skip look-alike chars (0 O 1 l I |)\n"
"  -r, --no-repeat       no character appears twice\n"
"\n"
"Minimum counts:\n"
"      --min-lower N     at least N lowercase letters\n"
"      --min-upper N     at least N uppercase letters\n"
"      --min-digits N    at least N digits\n"
"      --min-symbols N   at least N symbols\n"
"\n"
"Other modes:\n"
"      --pin             digits only (use with -l)\n"
"      --hex             hex string (use with -l)\n"
"  -w, --words N         passphrase with N words (needs -f)\n"
"  -f, --wordlist FILE   wordlist, one word per line (EFF diceware works)\n"
"  -d, --delimiter STR   word separator (default '-')\n"
"  -C, --capitalize      capitalize each word\n"
"\n"
"Examples:\n"
"  pwgen\n"
"  pwgen -l 24 -n 5 --min-digits 3 --min-symbols 2\n"
"  pwgen -l 20 -a -x \"{}[]\" -y '!@#_'\n"
"  pwgen --pin -l 6\n"
"  pwgen -w 5 -f eff_large_wordlist.txt -C -d .\n",
        to);
}

/* ---------- main ---------- */

int main(int argc, char **argv)
{
    Config cfg = {
        .mode = MODE_PASSWORD, .length = 16, .count = 1,
        .use_lower = 1, .use_upper = 1, .use_digits = 1, .use_symbols = 1,
        .symbols = SYMBOLS, .delim = "-",
    };

    static const struct option longopts[] = {
        {"length",       required_argument, 0, 'l'},
        {"count",        required_argument, 0, 'n'},
        {"output",       required_argument, 0, 'o'},
        {"quiet",        no_argument,       0, 'q'},
        {"help",         no_argument,       0, 'h'},
        {"version",      no_argument,       0, 'V'},
        {"no-lower",     no_argument,       0, 'L'},
        {"no-upper",     no_argument,       0, 'U'},
        {"no-digits",    no_argument,       0, 'D'},
        {"no-symbols",   no_argument,       0, 'S'},
        {"symbols",      required_argument, 0, 'y'},
        {"exclude",      required_argument, 0, 'x'},
        {"no-ambiguous", no_argument,       0, 'a'},
        {"no-repeat",    no_argument,       0, 'r'},
        {"min-lower",    required_argument, 0, OPT_MIN_LOWER},
        {"min-upper",    required_argument, 0, OPT_MIN_UPPER},
        {"min-digits",   required_argument, 0, OPT_MIN_DIGITS},
        {"min-symbols",  required_argument, 0, OPT_MIN_SYMBOLS},
        {"pin",          no_argument,       0, OPT_PIN},
        {"hex",          no_argument,       0, OPT_HEX},
        {"words",        required_argument, 0, 'w'},
        {"wordlist",     required_argument, 0, 'f'},
        {"delimiter",    required_argument, 0, 'd'},
        {"capitalize",   no_argument,       0, 'C'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "l:n:o:qhVLUDSy:x:arw:f:d:C", longopts, NULL)) != -1) {
        switch (opt) {
        case 'l': cfg.length = parse_int(optarg, 1, MAX_LEN, "length"); break;
        case 'n': cfg.count  = parse_int(optarg, 1, MAX_COUNT, "count"); break;
        case 'o': cfg.outfile = optarg; break;
        case 'q': cfg.quiet = 1; break;
        case 'h': usage(stdout); return 0;
        case 'V': puts("pwgen " VERSION); return 0;
        case 'L': cfg.use_lower = 0; break;
        case 'U': cfg.use_upper = 0; break;
        case 'D': cfg.use_digits = 0; break;
        case 'S': cfg.use_symbols = 0; break;
        case 'y': cfg.symbols = optarg; break;
        case 'x': cfg.exclude = optarg; break;
        case 'a': cfg.no_ambiguous = 1; break;
        case 'r': cfg.no_repeat = 1; break;
        case OPT_MIN_LOWER:   cfg.min_lower   = parse_int(optarg, 0, MAX_LEN, "--min-lower"); break;
        case OPT_MIN_UPPER:   cfg.min_upper   = parse_int(optarg, 0, MAX_LEN, "--min-upper"); break;
        case OPT_MIN_DIGITS:  cfg.min_digits  = parse_int(optarg, 0, MAX_LEN, "--min-digits"); break;
        case OPT_MIN_SYMBOLS: cfg.min_symbols = parse_int(optarg, 0, MAX_LEN, "--min-symbols"); break;
        case OPT_PIN: cfg.mode = MODE_PIN; break;
        case OPT_HEX: cfg.mode = MODE_HEX; break;
        case 'w': cfg.mode = MODE_PHRASE; cfg.words = parse_int(optarg, 1, 50, "words"); break;
        case 'f': cfg.wordlist = optarg; break;
        case 'd': cfg.delim = optarg; break;
        case 'C': cfg.capitalize = 1; break;
        default:  usage(stderr); return 1;
        }
    }
    if (optind < argc)
        die("unexpected argument '%s' (try --help)", argv[optind]);

    urandom = fopen("/dev/urandom", "rb");
    if (!urandom)
        die("can't open /dev/urandom: %s", strerror(errno));

    /* ----- set up pools / wordlist depending on mode ----- */
    Pool cls[4] = {{{0}, 0}}, all = {{0}, 0};
    char **words = NULL;
    size_t nwords = 0;
    double bits = 0;

    if (cfg.mode == MODE_PASSWORD) {
        if (cfg.use_lower)   pool_build(&cls[0], LOWER, &cfg, 0);
        if (cfg.use_upper)   pool_build(&cls[1], UPPER, &cfg, 0);
        if (cfg.use_digits)  pool_build(&cls[2], DIGITS, &cfg, 0);
        if (cfg.use_symbols) pool_build(&cls[3], cfg.symbols, &cfg, 1);

        const int mins[4] = { cfg.min_lower, cfg.min_upper, cfg.min_digits, cfg.min_symbols };
        const char *names[4] = { "lowercase", "uppercase", "digit", "symbol" };
        int total_min = 0;
        for (int k = 0; k < 4; k++) {
            if (mins[k] > 0 && cls[k].n == 0)
                die("asked for %s chars but that set is empty", names[k]);
            if (cfg.no_repeat && mins[k] > (int)cls[k].n)
                die("--no-repeat: only %zu distinct %s chars available", cls[k].n, names[k]);
            total_min += mins[k];
            pool_append(&all, &cls[k]);
        }
        if (all.n == 0)
            die("no characters left to choose from");
        if (total_min > cfg.length)
            die("minimums add up to %d, which is longer than --length %d", total_min, cfg.length);
        if (cfg.no_repeat && cfg.length > (int)all.n)
            die("--no-repeat: length %d is more than the %zu distinct chars available",
                cfg.length, all.n);
        bits = cfg.length * log2((double)all.n);
    } else if (cfg.mode == MODE_PIN || cfg.mode == MODE_HEX) {
        pool_build(&all, cfg.mode == MODE_PIN ? DIGITS : HEXCHARS, &cfg, 0);
        if (all.n == 0)
            die("no characters left to choose from");
        if (cfg.no_repeat && cfg.length > (int)all.n)
            die("--no-repeat: length %d is more than the %zu distinct chars available",
                cfg.length, all.n);
        bits = cfg.length * log2((double)all.n);
    } else {
        if (!cfg.wordlist)
            die("passphrase mode needs a wordlist (-f FILE)");
        words = load_words(cfg.wordlist, &nwords);
        bits = cfg.words * log2((double)nwords);
    }

    /* ----- output ----- */
    FILE *out = stdout;
    if (cfg.outfile) {
        umask(077);
        out = fopen(cfg.outfile, "a");
        if (!out)
            die("can't open '%s': %s", cfg.outfile, strerror(errno));
    }

    char *buf = NULL;
    if (cfg.mode != MODE_PHRASE) {
        buf = malloc((size_t)cfg.length + 1);
        if (!buf)
            die("out of memory");
    }

    for (int i = 0; i < cfg.count; i++) {
        if (cfg.mode == MODE_PHRASE) {
            buf = gen_phrase(&cfg, words, nwords);
        } else {
            gen_password(&cfg, cls, &all, buf);
        }
        fprintf(out, "%s\n", buf);
        wipe(buf, strlen(buf));
        if (cfg.mode == MODE_PHRASE) {
            free(buf);
            buf = NULL;
        }
    }

    if (!cfg.quiet)
        fprintf(stderr, "entropy ~ %.1f bits (%s)\n", bits, strength(bits));

    free(buf);
    if (cfg.outfile)
        fclose(out);
    for (size_t i = 0; i < nwords; i++)
        free(words[i]);
    free(words);
    fclose(urandom);
    return 0;
}
