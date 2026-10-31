// memguard: polls macOS VM + memorystatus_level + swap + per-process phys_footprint every 1s;
// SIGKILLs only the selected unprotected PID (or soft-protected PID at panic level).
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <stddef.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <libproc.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <mach/mach.h>

#define MAX_PROTECTED      256
#define MAX_NAME_LEN       256
#define GIB_BYTES          1073741824.0
#define MIB_BYTES          1048576.0
#define LAUNCHD_LABEL      "local.memguard"

extern char **environ;

#undef PROT_NONE
enum { PROT_NONE = 0, PROT_SOFT = 1, PROT_HARD = 2 };

typedef struct {
    char pat[MAX_NAME_LEN];
    uint16_t len;
    uint8_t is_prefix;
    uint8_t tier;
} prot_rule_t;

typedef struct {
    prot_rule_t rules[MAX_PROTECTED];
    int protected_count;
    double max_ram_fraction;
    double panic_ram_fraction;
    double fast_poll_ram_fraction;
    double poll_interval_ms;
    double fast_poll_interval_ms;
    double max_swap_gib;
    double swap_burst_floor_mib;
    double min_victim_gib;
    double kill_cooldown_s;
} conf_t;

// shortcut: polls in userspace since SIP prevents disabling kernel dynamic_pager, upgrade to Recovery OS vm_compressor=2 if sub-poll_interval kernel allocation spikes bypass it
static conf_t g_conf;
// load_conf parses here and only copies into g_conf once valid, so a bad reload never disarms the daemon.
static conf_t g_conf_next;
static volatile sig_atomic_t g_reload = 0;
static char g_service[64];
static pid_t g_pids[16384];
static int g_swap_mib[4];
static size_t g_swap_mib_len = 0;
static int g_memlevel_mib[4];
static size_t g_memlevel_mib_len = 0;

static void init_sysctl_mibs(void) {
    size_t len = 4;
    if (sysctlnametomib("vm.swapusage", g_swap_mib, &len) == 0) g_swap_mib_len = len;
    len = 4;
    if (sysctlnametomib("kern.memorystatus_level", g_memlevel_mib, &len) == 0) g_memlevel_mib_len = len;
}

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "SELF-TEST FAILED at %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        return 1; \
    } \
} while (0)

static int protection_tier(const char *name) {
    if (!name || !*name) return PROT_HARD;
    char lname[MAX_NAME_LEN];
    size_t nlen = 0;
    while (name[nlen] && nlen < sizeof(lname) - 1) {
        lname[nlen] = (char)tolower((unsigned char)name[nlen]);
        nlen++;
    }
    lname[nlen] = '\0';
    char c0 = lname[0];
    for (int i = 0; i < g_conf.protected_count; i++) {
        const prot_rule_t *r = &g_conf.rules[i];
        if (c0 != r->pat[0]) continue;
        if (r->is_prefix) {
            if (nlen >= r->len && memcmp(lname, r->pat, r->len) == 0) return r->tier;
        } else {
            if (nlen == r->len && memcmp(lname, r->pat, r->len) == 0) return r->tier;
        }
    }
    return PROT_NONE;
}

static char *trim(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1])) s[--len] = '\0';
    return s;
}

typedef struct {
    const char *name;
    size_t offset;
    double min, max;
    int fraction;
} conf_key_t;

#define CONF_KEY(name, min, max, fraction) {#name, offsetof(conf_t, name), min, max, fraction}
static const conf_key_t conf_keys[] = {
    CONF_KEY(max_ram_fraction, 0.10, 1.0, 1),
    CONF_KEY(panic_ram_fraction, 0.10, 1.0, 1),
    CONF_KEY(fast_poll_ram_fraction, 0.10, 1.0, 1),
    CONF_KEY(poll_interval_ms, 10.0, 60000.0, 0),
    CONF_KEY(fast_poll_interval_ms, 10.0, 60000.0, 0),
    CONF_KEY(max_swap_gib, 0.0, 1024.0, 0),
    CONF_KEY(swap_burst_floor_mib, 0.0, 1048576.0, 0),
    CONF_KEY(min_victim_gib, 0.05, 1024.0, 0),
    CONF_KEY(kill_cooldown_s, 0.0, 3600.0, 0),
};
#undef CONF_KEY

static double *conf_value(conf_t *c, const conf_key_t *key) {
    return (double *)((char *)c + key->offset);
}

static void init_conf(conf_t *c) {
    memset(c, 0, sizeof(*c));
    for (size_t i = 0; i < sizeof(conf_keys) / sizeof(conf_keys[0]); i++)
        *conf_value(c, &conf_keys[i]) = -1.0;
}

static const char *parse_conf_line(conf_t *c, char *line) {
    char *comment = strchr(line, '#');
    if (comment) *comment = '\0';
    char *p = trim(line);
    if (!*p) return NULL;
    char *eq = strchr(p, '=');
    if (eq) {
        *eq = '\0';
        char *k = trim(p), *v = trim(eq + 1);
        for (size_t i = 0; i < sizeof(conf_keys) / sizeof(conf_keys[0]); i++) {
            const conf_key_t *key = &conf_keys[i];
            if (strcmp(k, key->name) != 0) continue;
            double *dest = conf_value(c, key);
            if (*dest >= 0.0) return "duplicate numeric key";
            char *end;
            errno = 0;
            double val = strtod(v, &end);
            if (errno || end == v || *end || !isfinite(val)) return "invalid numeric value";
            if (key->fraction && val > 1.0) val /= 100.0;
            if (val < key->min || val > key->max) return "numeric value out of range";
            *dest = val;
            return NULL;
        }
        return "unknown numeric key";
    }

    uint8_t tier = PROT_SOFT;
    if (*p == '!') {
        tier = PROT_HARD;
        p = trim(p + 1);
    }
    size_t plen = strlen(p);
    uint8_t is_prefix = plen > 0 && p[plen - 1] == '*';
    if (is_prefix) p[--plen] = '\0';
    if (!plen || strchr(p, '!') || strchr(p, '*')) return "malformed protection rule";
    if (plen >= MAX_NAME_LEN) return "protection name too long";
    if (c->protected_count == MAX_PROTECTED) return "too many protection rules";
    prot_rule_t rule = {0};
    for (size_t i = 0; i < plen; i++) rule.pat[i] = (char)tolower((unsigned char)p[i]);
    rule.len = (uint16_t)plen;
    rule.is_prefix = is_prefix;
    rule.tier = tier;
    // Hard rules precede soft rules so protection_tier needs only one pass.
    int at = c->protected_count;
    if (tier == PROT_HARD) {
        at = 0;
        while (at < c->protected_count && c->rules[at].tier == PROT_HARD) at++;
        memmove(&c->rules[at + 1], &c->rules[at],
                (size_t)(c->protected_count - at) * sizeof(rule));
    }
    c->rules[at] = rule;
    c->protected_count++;
    return NULL;
}

static const char *validate_conf(conf_t *c) {
    for (size_t i = 0; i < sizeof(conf_keys) / sizeof(conf_keys[0]); i++)
        if (*conf_value(c, &conf_keys[i]) < 0.0) return "missing numeric key";
    if (!c->protected_count) return "no protection rules";
    if (c->fast_poll_ram_fraction > c->max_ram_fraction ||
        c->max_ram_fraction > c->panic_ram_fraction) return "invalid RAM threshold ordering";
    return NULL;
}

static int load_conf(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "memguard: %s:1: %s\n", path, strerror(errno));
        return -1;
    }
    conf_t *c = &g_conf_next;
    init_conf(c);
    char line[1024];
    size_t used = 0, lineno = 1;
    int ch;
    const char *error = NULL;
    while ((ch = fgetc(f)) != EOF) {
        if (!ch) { error = "embedded NUL byte"; break; }
        if (ch == '\n') {
            line[used] = '\0';
            error = parse_conf_line(c, line);
            if (error) break;
            used = 0;
            lineno++;
        } else {
            if (used == sizeof(line) - 1) { error = "line too long"; break; }
            line[used++] = (char)ch;
        }
    }
    if (!error && ferror(f)) error = "config read error";
    if (!error && used) {
        line[used] = '\0';
        error = parse_conf_line(c, line);
    }
    if (fclose(f) != 0 && !error) error = "config close error";
    if (!error) error = validate_conf(c);
    if (error) {
        fprintf(stderr, "memguard: %s:%zu: %s\n", path, lineno, error);
        return -1;
    }
    memcpy(&g_conf, c, sizeof(g_conf));
    return 0;
}

static void on_sighup(int sig) {
    (void)sig;
    g_reload = 1;
}

static int wait_poll(useconds_t us, const sigset_t *wait_mask) {
    if (g_reload) return 0;
    struct timespec timeout = {us / 1000000, (long)(us % 1000000) * 1000};
    if (pselect(0, NULL, NULL, NULL, &timeout, wait_mask) < 0 && errno != EINTR) {
        perror("memguard: pselect");
        return -1;
    }
    return 0;
}

// Runs /bin/launchctl with a fixed argv (a2/a3 may be NULL). quiet discards its output; out captures its stdout.
static int launchctl(const char *a1, const char *a2, const char *a3, int quiet, char *out, size_t out_len) {
    char *args[] = {"launchctl", (char *)a1, (char *)a2, (char *)a3, NULL};
    int pfd[2] = {-1, -1};
    if (out && pipe(pfd) != 0) return -1;
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    if (out) {
        posix_spawn_file_actions_adddup2(&fa, pfd[1], STDOUT_FILENO);
        posix_spawn_file_actions_addclose(&fa, pfd[0]);
        posix_spawn_file_actions_addclose(&fa, pfd[1]);
    } else if (quiet) {
        posix_spawn_file_actions_addopen(&fa, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
    }
    if (out || quiet) posix_spawn_file_actions_addopen(&fa, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
    pid_t pid;
    int rc = posix_spawn(&pid, "/bin/launchctl", &fa, NULL, args, environ);
    posix_spawn_file_actions_destroy(&fa);
    if (out) {
        close(pfd[1]);
        size_t n = 0;
        ssize_t r;
        char drain[4096];
        // Keep reading past a full buffer so launchctl never blocks on the pipe.
        while (rc == 0 && (r = read(pfd[0], n + 1 < out_len ? out + n : drain,
                                    n + 1 < out_len ? out_len - 1 - n : sizeof(drain))) != 0) {
            if (r < 0) {
                if (errno == EINTR) continue;
                break;
            }
            if (n + 1 < out_len) n += (size_t)r;
        }
        out[n] = '\0';
        close(pfd[0]);
    }
    if (rc != 0) return -1;
    int st = 0;
    while (waitpid(pid, &st, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

// Returns pid, 0 if loaded but stopped, -1 if not loaded, or -2 on query failure.
static pid_t daemon_pid(void) {
    char buf[16384];
    int rc = launchctl("print", g_service, NULL, 0, buf, sizeof(buf));
    if (rc == 113) return -1; // launchctl's service-not-found status.
    if (rc != 0) {
        fprintf(stderr, "memguard: launchctl status unavailable (exit %d)\n", rc);
        return -2;
    }
    char *p = strstr(buf, "\n\tpid = ");
    return p ? (pid_t)atoi(p + 8) : 0;
}

static int control(const char *cmd, const char *conf_path) {
    if (strcmp(cmd, "stop") == 0) {
        pid_t pid = daemon_pid();
        if (pid == -2) return 1;
        if (pid == -1) {
            printf("memguard: not loaded\n");
            return 0;
        }
        // bootout rather than kill: KeepAlive would respawn a killed daemon immediately.
        if (launchctl("bootout", g_service, NULL, 0, NULL, 0) != 0) return 1;
        printf("memguard: stopped (starts again at next login, or run: memguard start)\n");
        return 0;
    }
    // Everything else (re)starts the daemon on the on-disk config, so reject a bad one here instead of in the log.
    if (load_conf(conf_path) != 0) return 1;
    if (strcmp(cmd, "check") == 0) {
        printf("memguard: %s ok (%d protected rules)\n", conf_path, g_conf.protected_count);
        return 0;
    }
    pid_t pid = daemon_pid();
    if (pid == -2) return 1;
    if (strcmp(cmd, "reload") == 0) {
        if (pid <= 0) {
            fprintf(stderr, "memguard: daemon not running (run: memguard start)\n");
            return 1;
        }
        if (launchctl("kill", "SIGHUP", g_service, 0, NULL, 0) != 0) return 1;
        printf("memguard: sent SIGHUP to pid %d (result in log)\n", pid);
        return 0;
    }
    if (strcmp(cmd, "start") == 0 && pid > 0) {
        printf("memguard: already running (pid %d)\n", pid);
        return 0;
    }
    if (pid >= 0) {
        if (launchctl("kickstart", "-k", g_service, 0, NULL, 0) != 0) return 1;
    } else {
        const char *home = getenv("HOME");
        char plist[1024], domain[32];
        if (!home || !*home) {
            fprintf(stderr, "memguard: HOME is required\n");
            return 1;
        }
        int plen = snprintf(plist, sizeof(plist), "%s/Library/LaunchAgents/%s.plist", home, LAUNCHD_LABEL);
        if (plen < 0 || (size_t)plen >= sizeof(plist)) {
            fprintf(stderr, "memguard: LaunchAgent path too long\n");
            return 1;
        }
        snprintf(domain, sizeof(domain), "gui/%u", (unsigned)getuid());
        if (access(plist, R_OK) != 0) {
            fprintf(stderr, "memguard: %s not found (run: just enable)\n", plist);
            return 1;
        }
        if (launchctl("bootstrap", domain, plist, 0, NULL, 0) != 0) return 1;
    }
    printf("memguard: %s\n", pid > 0 ? "restarted" : "started");
    return 0;
}

enum { TRIG_NONE = 0, TRIG_NORMAL = 1, TRIG_PANIC = 2 };

static int should_trigger(double effective_ram_fraction, uint64_t sys_used, uint64_t memsize,
                          double max_ram_fraction, double panic_ram_fraction,
                          uint64_t swap_used, uint64_t min_swap_used,
                          uint64_t max_swap_allowance, uint64_t swap_burst_floor,
                          uint64_t swapouts, uint64_t prev_swapouts,
                          const char **reason_out) {
    if (effective_ram_fraction >= panic_ram_fraction) {
        *reason_out = "PANIC_RAM";
        return TRIG_PANIC;
    }
    if (effective_ram_fraction >= max_ram_fraction) {
        *reason_out = "RAM_LIMIT";
        return TRIG_NORMAL;
    }
    if (prev_swapouts != UINT64_MAX && swapouts > prev_swapouts && swap_used > min_swap_used) {
        uint64_t swap_growth = swap_used - min_swap_used;
        if (max_swap_allowance == 0 && sys_used < memsize / 2 && swap_burst_floor > 0) {
            if (swap_growth >= swap_burst_floor) {
                *reason_out = "SWAP_LIMIT";
                return TRIG_NORMAL;
            }
        } else if (swap_growth > max_swap_allowance) {
            *reason_out = "SWAP_LIMIT";
            return TRIG_NORMAL;
        }
    }
    *reason_out = "OK";
    return TRIG_NONE;
}

static int get_swap_used(uint64_t *out) {
    struct xsw_usage xsu;
    size_t len = sizeof(xsu);
    int rc = g_swap_mib_len
        ? sysctl(g_swap_mib, (u_int)g_swap_mib_len, &xsu, &len, NULL, 0)
        : sysctlbyname("vm.swapusage", &xsu, &len, NULL, 0);
    if (rc == 0) {
        *out = xsu.xsu_used;
        return 0;
    }
    return -1;
}

static int get_memorystatus_level(void) {
    int level = 100;
    size_t len = sizeof(level);
    int rc = g_memlevel_mib_len
        ? sysctl(g_memlevel_mib, (u_int)g_memlevel_mib_len, &level, &len, NULL, 0)
        : sysctlbyname("kern.memorystatus_level", &level, &len, NULL, 0);
    if (rc == 0 && level >= 0 && level <= 100) {
        return level;
    }
    return -1;
}

static const char *status_eligibility(uint64_t footprint, uint64_t minimum, int soft) {
    if (footprint < minimum) return "below minimum";
    return soft ? "panic only" : "eligible at normal threshold";
}

static void status_text(const char *text) {
    for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
        if (p[0] == 0xC2 && p[1] >= 0x80 && p[1] <= 0x9F) {
            putchar('?');
            p++;
        } else {
            putchar(iscntrl(*p) ? '?' : *p);
        }
    }
}

static void status_process(const char *label, pid_t pid, const char *name,
                           uint64_t footprint, uint64_t minimum, int soft) {
    printf("  %-16s", label);
    if (pid <= 1) {
        puts("none observed");
        return;
    }
    status_text(name);
    printf("  PID %d · %.2f GiB · %s\n", pid, footprint / GIB_BYTES,
           status_eligibility(footprint, minimum, soft));
}

static int verify_target(pid_t pid, uint64_t start, const char *expected_name, int tier,
                         uint64_t min_bytes, char *name, struct rusage_info_v0 *ri) {
    if (pid <= 1 || pid == getpid()) return 0;
    return proc_name(pid, name, MAX_NAME_LEN) > 0 &&
           strcmp(name, expected_name) == 0 && protection_tier(name) <= tier &&
           proc_pid_rusage(pid, RUSAGE_INFO_V0, (rusage_info_t *)ri) == 0 &&
           ri->ri_proc_start_abstime == start && ri->ri_phys_footprint >= min_bytes;
}

static void notify_kill(const char *reason, const char *name, pid_t pid, double gib) {
    pid_t child = fork();
    if (child == 0) {
        signal(SIGCHLD, SIG_DFL);
        char safe_name[64] = {0};
        size_t j = 0;
        for (size_t i = 0; name[i] && j < sizeof(safe_name) - 1; i++) {
            if (isalnum((unsigned char)name[i]) || name[i] == '_' || name[i] == '-' || name[i] == '.') {
                safe_name[j++] = name[i];
            }
        }
        char script[256];
        snprintf(script, sizeof(script),
                 "display notification \"Killed %s (pid %d, %.1f GiB) [%s]\" with title \"memguard\"",
                 safe_name[0] ? safe_name : "process", pid, gib, reason);
        execl("/usr/bin/osascript", "osascript", "-e", script, (char *)NULL);
        _exit(0);
    }
}

static int run_hog_mode(mach_port_t host_port, vm_size_t page_size, uint64_t memsize) {
    const char *allow = getenv("MEMGUARD_ALLOW_STRESS");
    if (!allow || strcmp(allow, "1") != 0) {
        fprintf(stderr, "memguard: --hog requires MEMGUARD_ALLOW_STRESS=1; it can kill unrelated work\n");
        return 1;
    }
    fprintf(stderr, "DANGER: --hog drives RAM to 98%% and can trigger SIGKILL of unrelated work; unsaved data may be lost.\n");
    alarm(60);
    uint64_t target = (uint64_t)((double)memsize * 0.98);
    size_t chunk_size = 512ULL * 1024ULL * 1024ULL;
    uint64_t allocated = 0;
    uint64_t rng = 0x9e3779b97f4a7c15ULL ^ (uint64_t)getpid();
    printf("memguard --hog pid=%d target=98%% (%.2f / %.2f GiB)\n",
           getpid(), target / GIB_BYTES, memsize / GIB_BYTES);
    fflush(stdout);
    while (allocated < memsize) {
        vm_statistics64_data_t vm;
        mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
        if (host_statistics64(host_port, HOST_VM_INFO64, (host_info64_t)&vm, &count) == KERN_SUCCESS) {
            uint64_t internal = vm.internal_page_count > vm.purgeable_count ? vm.internal_page_count - vm.purgeable_count : 0;
            uint64_t sys_used = (vm.wire_count + vm.compressor_page_count + internal) * page_size;
            if (sys_used >= target) {
                printf("memguard --hog reached %.1f%% (%.2f GiB), holding for 15s...\n",
                       100.0 * sys_used / memsize, sys_used / GIB_BYTES);
                fflush(stdout);
                sleep(15);
                return 0;
            }
        }
        volatile uint64_t *buf = (volatile uint64_t *)mmap(NULL, chunk_size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
        if (buf == MAP_FAILED) {
            usleep(100000);
            continue;
        }
        size_t words = chunk_size / sizeof(uint64_t);
        for (size_t i = 0; i < words; i++) {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            buf[i] = rng;
        }
        allocated += chunk_size;
        if ((allocated % (4ULL << 30)) == 0) {
            printf("memguard --hog allocated=%.1f GiB\n", allocated / GIB_BYTES);
            fflush(stdout);
        }
    }
    return 1;
}

int main(int argc, char **argv) {
    // No argument = daemon mode, which is what the LaunchAgent runs.
    const char *cmd = argc == 2 ? argv[1] : "run";
    if (strcmp(cmd, "--status") == 0) cmd = "status";
    int run = (strcmp(cmd, "run") == 0);
    int dry_run = (strcmp(cmd, "--dry-run") == 0);
    int help = (strcmp(cmd, "--help") == 0);
    int once = (strcmp(cmd, "status") == 0);
    int selftest = (strcmp(cmd, "--self-test") == 0);
    int hog = (strcmp(cmd, "--hog") == 0);
    int ctl = (strcmp(cmd, "start") == 0 || strcmp(cmd, "stop") == 0 || strcmp(cmd, "restart") == 0 ||
               strcmp(cmd, "reload") == 0 || strcmp(cmd, "check") == 0);
    if (help || argc > 2 || (!run && !dry_run && !once && !selftest && !hog && !ctl)) {
        fprintf(help && argc == 2 ? stdout : stderr,
                "usage: memguard [command]\n"
                "  run       run the daemon in the foreground (default; what the LaunchAgent runs)\n"
                "  --dry-run observe in the foreground; log WOULD_KILL without signals or notifications\n"
                "  --help    print this help without reading config\n"
                "  status    print daemon state, RAM/pressure/swap snapshot and largest processes\n"
                "  check     validate ~/.config/memguard/memguard.conf\n"
                "  start     load the LaunchAgent\n"
                "  stop      unload the LaunchAgent until next login or 'memguard start'\n"
                "  restart   restart the daemon (picks up a newly installed binary)\n"
                "  reload    re-read the config in the running daemon (SIGHUP)\n"
                "  --self-test run isolated source checks using ./memguard.conf\n"
                "  --hog     DANGER: stress RAM to 98%%; requires MEMGUARD_ALLOW_STRESS=1\n");
        return help && argc == 2 ? 0 : 2;
    }

    char conf_path[1024];
    if (selftest) {
        snprintf(conf_path, sizeof(conf_path), "memguard.conf");
    } else if (!hog) {
        const char *home = getenv("HOME");
        if (!home || !*home) {
            fprintf(stderr, "memguard: HOME is required\n");
            return 1;
        }
        int plen = snprintf(conf_path, sizeof(conf_path), "%s/.config/memguard/memguard.conf", home);
        if (plen < 0 || (size_t)plen >= sizeof(conf_path)) {
            fprintf(stderr, "memguard: config path too long\n");
            return 1;
        }
    }
    snprintf(g_service, sizeof(g_service), "gui/%u/%s", (unsigned)getuid(), LAUNCHD_LABEL);
    if (ctl) return control(cmd, conf_path);

    if (selftest) {
        const char *reason = NULL;
        char l1[] = "max_ram_fraction = 0.90";
        char l2[] = "panic_ram_fraction = 0.97";
        char l3[] = "fast_poll_ram_fraction = 0.80";
        char l4[] = "poll_interval_ms = 1000";
        char l5[] = "fast_poll_interval_ms = 200";
        char l6[] = "max_swap_gib = 0.5";
        char l7[] = "swap_burst_floor_mib = 64";
        char l8[] = "min_victim_gib = 3.0";
        char l9[] = "kill_cooldown_s = 15";
        char l10[] = "!Ghostty*";
        char l11[] = "Safari*";
        char lbad[] = "max_ram_fraction = 0.50oops";
        init_conf(&g_conf);
        CHECK(parse_conf_line(&g_conf, lbad) != NULL);
        CHECK(parse_conf_line(&g_conf, l1) == NULL);
        CHECK(parse_conf_line(&g_conf, l2) == NULL);
        CHECK(parse_conf_line(&g_conf, l3) == NULL);
        CHECK(parse_conf_line(&g_conf, l4) == NULL);
        CHECK(parse_conf_line(&g_conf, l5) == NULL);
        CHECK(parse_conf_line(&g_conf, l6) == NULL);
        CHECK(parse_conf_line(&g_conf, l7) == NULL);
        CHECK(parse_conf_line(&g_conf, l8) == NULL);
        CHECK(parse_conf_line(&g_conf, l9) == NULL);
        CHECK(validate_conf(&g_conf) != NULL);
        CHECK(parse_conf_line(&g_conf, l10) == NULL);
        CHECK(parse_conf_line(&g_conf, l11) == NULL);
        CHECK(validate_conf(&g_conf) == NULL);
        const char *invalid[] = {"!", "*", "!*", "a!b", "a*b", "unknown = 1",
                                 "max_swap_gib = nan", "min_victim_gib = 1e999",
                                 "max_ram_fraction = 101", "poll_interval_ms = 9",
                                 "max_swap_gib = 1025", "min_victim_gib = 1e-9999",
                                 "kill_cooldown_s = -1", "kill_cooldown_s = 3601"};
        static conf_t scratch;
        for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
            char line[128];
            strlcpy(line, invalid[i], sizeof(line));
            init_conf(&scratch);
            CHECK(parse_conf_line(&scratch, line) != NULL);
        }
        char duplicate[] = "poll_interval_ms = 2000";
        CHECK(parse_conf_line(&g_conf, duplicate) != NULL);
        char long_name[MAX_NAME_LEN + 1];
        memset(long_name, 'x', MAX_NAME_LEN);
        long_name[MAX_NAME_LEN] = '\0';
        CHECK(parse_conf_line(&g_conf, long_name) != NULL);
        init_conf(&scratch);
        for (int i = 0; i < MAX_PROTECTED; i++) {
            char rule[] = "!rule";
            CHECK(parse_conf_line(&scratch, rule) == NULL);
        }
        char overflow[] = "!one-too-many";
        CHECK(parse_conf_line(&scratch, overflow) != NULL);
        memcpy(&scratch, &g_conf, sizeof(scratch));
        scratch.max_ram_fraction = 0.99;
        CHECK(validate_conf(&scratch) != NULL);
        scratch.max_ram_fraction = 0.90;
        scratch.fast_poll_ram_fraction = 0.91;
        CHECK(validate_conf(&scratch) != NULL);
        char spaced[] = "!A process (helper).app* # trailing comment";
        CHECK(parse_conf_line(&g_conf, spaced) == NULL);
        CHECK(protection_tier("A process (helper).app worker") == PROT_HARD);
        CHECK(g_conf.max_ram_fraction == 0.90);
        CHECK(g_conf.panic_ram_fraction == 0.97);
        CHECK(g_conf.fast_poll_ram_fraction == 0.80);
        CHECK(g_conf.poll_interval_ms == 1000.0);
        CHECK(g_conf.fast_poll_interval_ms == 200.0);
        CHECK(g_conf.max_swap_gib == 0.5);
        CHECK(g_conf.swap_burst_floor_mib == 64.0);
        CHECK(g_conf.min_victim_gib == 3.0);
        CHECK(g_conf.kill_cooldown_s == 15.0);
        CHECK(protection_tier("ghostty") == PROT_HARD);
        CHECK(protection_tier("Safari WebContent") == PROT_SOFT);
        CHECK(protection_tier("") == PROT_HARD);
        CHECK(protection_tier("python3.13") == PROT_NONE);

        uint64_t mem = 100ULL << 30;
        uint64_t floor = 64ULL << 20;
        CHECK(should_trigger(0.20, 20ULL << 30, mem, 0.95, 0.98, (10ULL << 30) + (8ULL << 20), 10ULL << 30, 0, floor, 105, 100, &reason) == TRIG_NONE);
        CHECK(should_trigger(0.20, 20ULL << 30, mem, 0.95, 0.98, (10ULL << 30) + (64ULL << 20), 10ULL << 30, 0, floor, 105, 100, &reason) == TRIG_NORMAL && strcmp(reason, "SWAP_LIMIT") == 0);
        CHECK(should_trigger(0.20, 20ULL << 30, mem, 0.95, 0.98, (10ULL << 30) + (128ULL << 20), UINT64_MAX, 0, floor, 105, 100, &reason) == TRIG_NONE);
        CHECK(should_trigger(0.55, 55ULL << 30, mem, 0.95, 0.98, (10ULL << 30) + (8ULL << 20), 10ULL << 30, 0, floor, 105, 100, &reason) == TRIG_NORMAL && strcmp(reason, "SWAP_LIMIT") == 0);
        CHECK(should_trigger(0.95, 85ULL << 30, mem, 0.95, 0.98, 0, 0, 0, floor, 100, 100, &reason) == TRIG_NORMAL && strcmp(reason, "RAM_LIMIT") == 0);
        CHECK(should_trigger(0.98, 88ULL << 30, mem, 0.95, 0.98, 0, 0, 0, floor, 100, 100, &reason) == TRIG_PANIC && strcmp(reason, "PANIC_RAM") == 0);
        CHECK(strcmp(status_eligibility(99, 100, 0), "below minimum") == 0);
        CHECK(strcmp(status_eligibility(100, 100, 0), "eligible at normal threshold") == 0);
        CHECK(strcmp(status_eligibility(100, 100, 1), "panic only") == 0);
        once = 1;
    }

    if (!hog && load_conf(conf_path) != 0) return 1;
    pid_t dpid = 0;
    if (once && !selftest && (dpid = daemon_pid()) == -2) return 1;

    uint64_t memsize = 0;
    size_t len = sizeof(memsize);
    if (sysctlbyname("hw.memsize", &memsize, &len, NULL, 0) != 0 || memsize == 0) {
        fprintf(stderr, "memguard: total RAM unavailable\n");
        return 1;
    }

    mach_port_t host_port = mach_host_self();
    vm_size_t page_size = 16384;
    if (host_page_size(host_port, &page_size) != KERN_SUCCESS || page_size == 0) {
        fprintf(stderr, "memguard: VM page size unavailable\n");
        return 1;
    }
    if (hog) return run_hog_mode(host_port, page_size, memsize);

    pid_t self_pid = getpid();
    uid_t self_uid = getuid();
    init_sysctl_mibs();

    if (selftest) {
        CHECK(g_conf.protected_count > 0);
        CHECK(protection_tier("WindowServer") == PROT_HARD);
        CHECK(protection_tier("herdr") == PROT_HARD);
        CHECK(protection_tier("com.apple.WebKit.WebContent") == PROT_SOFT);
        CHECK(g_swap_mib_len > 0 && g_memlevel_mib_len > 0);
        CHECK(proc_listpids(PROC_UID_ONLY, (uint32_t)self_uid, g_pids, (int)sizeof(g_pids)) > 0);

        int ready_pipe[2], hold_pipe[2];
        CHECK(pipe(ready_pipe) == 0 && pipe(hold_pipe) == 0);
        fflush(stdout);
        pid_t child = fork();
        CHECK(child >= 0);
        if (child == 0) {
            alarm(30);
            close(ready_pipe[0]);
            close(hold_pipe[1]);
            size_t sz = 16ULL << 20;
            volatile char *p = (volatile char *)mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
            if (p == MAP_FAILED) _exit(2);
            for (size_t i = 0; i < sz; i += 4096) p[i] = (char)(i + 1);
            char b = 'R';
            (void)write(ready_pipe[1], &b, 1);
            (void)read(hold_pipe[0], &b, 1);
            _exit(0);
        }
        close(ready_pipe[1]);
        close(hold_pipe[0]);
        char b = 0;
        CHECK(read(ready_pipe[0], &b, 1) == 1 && b == 'R');
        close(ready_pipe[0]);

        pid_t sibling;
        char *sleep_args[] = {"sleep", "30", NULL};
        CHECK(posix_spawn(&sibling, "/bin/sleep", NULL, NULL, sleep_args, environ) == 0);
        char sleep_rule[] = "!sleep";
        CHECK(parse_conf_line(&g_conf, sleep_rule) == NULL);
        char sibling_name[MAX_NAME_LEN], cname[MAX_NAME_LEN], verified[MAX_NAME_LEN];
        struct rusage_info_v0 cri, sibling_ri, verified_ri;
        CHECK(proc_name(sibling, sibling_name, sizeof(sibling_name)) > 0);
        CHECK(protection_tier(sibling_name) == PROT_HARD);
        CHECK(proc_pid_rusage(sibling, RUSAGE_INFO_V0, (rusage_info_t *)&sibling_ri) == 0);
        CHECK(proc_pid_rusage(child, RUSAGE_INFO_V0, (rusage_info_t *)&cri) == 0);
        CHECK(cri.ri_phys_footprint >= (15ULL << 20));
        CHECK(proc_name(child, cname, sizeof(cname)) > 0);
        CHECK(!verify_target(child, cri.ri_proc_start_abstime ^ 1, cname, PROT_NONE,
                             15ULL << 20, verified, &verified_ri));
        CHECK(!verify_target(child, cri.ri_proc_start_abstime, "wrong-name", PROT_NONE,
                             15ULL << 20, verified, &verified_ri));
        CHECK(!verify_target(sibling, sibling_ri.ri_proc_start_abstime, sibling_name,
                             PROT_SOFT, 0, verified, &verified_ri));
        int ok = verify_target(child, cri.ri_proc_start_abstime, cname, PROT_NONE,
                               15ULL << 20, verified, &verified_ri) &&
                 kill(child, SIGKILL) == 0;
        close(hold_pipe[1]);
        int st = 0;
        pid_t wrc;
        do { wrc = waitpid(child, &st, 0); } while (wrc < 0 && errno == EINTR);
        CHECK(ok && wrc == child && WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL);
        CHECK(kill(sibling, 0) == 0);
        CHECK(kill(sibling, SIGKILL) == 0);
        do { wrc = waitpid(sibling, &st, 0); } while (wrc < 0 && errno == EINTR);
        CHECK(wrc == sibling);

        // A rejected reload must leave the live config byte-for-byte untouched.
        static conf_t saved;
        memcpy(&saved, &g_conf, sizeof(saved));
        char bad_path[] = "/tmp/memguard-selftest.XXXXXX";
        int fd = mkstemp(bad_path);
        CHECK(fd >= 0);
        const char numeric[] =
            "max_ram_fraction = 90\npanic_ram_fraction = 97\nfast_poll_ram_fraction = 80\n"
            "poll_interval_ms = 1000\nfast_poll_interval_ms = 200\nmax_swap_gib = 0.5\n"
            "swap_burst_floor_mib = 64\nmin_victim_gib = 3\nkill_cooldown_s = 15\n";
        const char *bad_rules[] = {"", "!", "!*", "*", "a*b", "unknown = 1",
                                  "max_ram_fraction = 90\n!rule"};
        fprintf(stderr, "memguard --self-test: expecting config errors next\n");
        for (size_t i = 0; i < sizeof(bad_rules) / sizeof(bad_rules[0]); i++) {
            CHECK(ftruncate(fd, 0) == 0 && lseek(fd, 0, SEEK_SET) == 0);
            CHECK(write(fd, numeric, sizeof(numeric) - 1) == (ssize_t)(sizeof(numeric) - 1));
            size_t size = strlen(bad_rules[i]);
            CHECK(write(fd, bad_rules[i], size) == (ssize_t)size);
            CHECK(load_conf(bad_path) != 0 && memcmp(&saved, &g_conf, sizeof(saved)) == 0);
        }
        CHECK(ftruncate(fd, 0) == 0 && lseek(fd, 0, SEEK_SET) == 0);
        CHECK(write(fd, "!only-rule\n", 11) == 11);
        CHECK(load_conf(bad_path) != 0);
        char long_line[1025];
        memset(long_line, 'x', sizeof(long_line));
        CHECK(ftruncate(fd, 0) == 0 && lseek(fd, 0, SEEK_SET) == 0);
        CHECK(write(fd, long_line, sizeof(long_line)) == (ssize_t)sizeof(long_line));
        CHECK(load_conf(bad_path) != 0);
        CHECK(ftruncate(fd, 0) == 0 && lseek(fd, 0, SEEK_SET) == 0);
        CHECK(write(fd, "a\0b", 3) == 3);
        CHECK(load_conf(bad_path) != 0);
        CHECK(close(fd) == 0 && unlink(bad_path) == 0);
        CHECK(load_conf(bad_path) != 0);
        CHECK(memcmp(&saved, &g_conf, sizeof(saved)) == 0);
    }

    sigset_t wait_mask;
    sigemptyset(&wait_mask);
    if (run || dry_run || selftest) {
        sigset_t blocked;
        sigemptyset(&blocked);
        sigaddset(&blocked, SIGHUP);
        if (sigprocmask(SIG_BLOCK, &blocked, &wait_mask) != 0) {
            perror("memguard: sigprocmask");
            return 1;
        }
        sigdelset(&wait_mask, SIGHUP);
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = on_sighup;
        sigemptyset(&sa.sa_mask);
        if (sigaction(SIGHUP, &sa, NULL) != 0) {
            perror("memguard: sigaction");
            return 1;
        }
    }
    if (selftest) {
        CHECK(raise(SIGHUP) == 0 && g_reload == 0);
        struct timespec before, after;
        CHECK(clock_gettime(CLOCK_MONOTONIC, &before) == 0);
        CHECK(wait_poll(5000000, &wait_mask) == 0 && g_reload == 1);
        CHECK(clock_gettime(CLOCK_MONOTONIC, &after) == 0);
        CHECK((double)(after.tv_sec - before.tv_sec) +
              (double)(after.tv_nsec - before.tv_nsec) * 1e-9 < 1.0);
        g_reload = 0;
    }

    signal(SIGCHLD, SIG_IGN);
    if (run || dry_run) {
        fprintf(stderr, "memguard: config=%s mode=%s\n", conf_path,
                dry_run ? "observation-only (no killing or notifications)" : "live");
        fprintf(stderr, "WARNING: live mode sends SIGKILL; unsaved data can be lost. Protection checks are best-effort.\n");
        fflush(stderr);
    }

    uint64_t min_swap_used = UINT64_MAX;
    uint64_t swap_used = 0;
    if (get_swap_used(&swap_used) == 0) min_swap_used = swap_used;
    uint64_t prev_swapouts = UINT64_MAX;
    unsigned int tick = 0;

    enum { COOLDOWN_SLOTS = 16 };
    pid_t killed_pids[COOLDOWN_SLOTS] = {0};
    struct timespec killed_ts[COOLDOWN_SLOTS] = {{0, 0}};
    unsigned int killed_idx = 0;
    time_t last_skip_log_time = 0;

    uint64_t max_swap_allowance = 0, swap_burst_floor = 0, min_victim_bytes = 0, fast_poll_bytes = 0;
    useconds_t poll_us = 0, fast_poll_us = 0;
    time_t kill_cooldown_s = 0;
    int conf_dirty = 1;

    for (;; tick++) {
        if (g_reload) {
            g_reload = 0;
            time_t now = time(NULL);
            char ts[32];
            strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S%z", localtime(&now));
            // Swap baseline and kill cooldowns are runtime state, not config, so they survive the reload.
            if (load_conf(conf_path) == 0) {
                conf_dirty = 1;
                fprintf(stderr, "[%s] RELOADED %s (%d protected rules)\n", ts, conf_path, g_conf.protected_count);
            } else {
                fprintf(stderr, "[%s] RELOAD_FAILED %s: keeping previous config\n", ts, conf_path);
            }
            fflush(stderr);
        }
        if (conf_dirty) {
            conf_dirty = 0;
            max_swap_allowance = (uint64_t)(g_conf.max_swap_gib * GIB_BYTES);
            swap_burst_floor = (uint64_t)(g_conf.swap_burst_floor_mib * MIB_BYTES);
            min_victim_bytes = (uint64_t)(g_conf.min_victim_gib * GIB_BYTES);
            fast_poll_bytes = (uint64_t)(g_conf.fast_poll_ram_fraction * (double)memsize);
            poll_us = (useconds_t)(g_conf.poll_interval_ms * 1000.0);
            fast_poll_us = (useconds_t)(g_conf.fast_poll_interval_ms * 1000.0);
            kill_cooldown_s = (time_t)g_conf.kill_cooldown_s;
        }

        vm_statistics64_data_t vm;
        mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
        if (host_statistics64(host_port, HOST_VM_INFO64, (host_info64_t)&vm, &count) == KERN_SUCCESS) {
            uint64_t wired = (uint64_t)vm.wire_count * page_size;
            uint64_t comp = (uint64_t)vm.compressor_page_count * page_size;
            uint64_t internal = (uint64_t)vm.internal_page_count;
            uint64_t purgeable = (uint64_t)vm.purgeable_count;
            uint64_t app = (internal > purgeable ? internal - purgeable : 0) * page_size;
            uint64_t sys_used = wired + comp + app;
            uint64_t total_cached = sys_used + (uint64_t)vm.external_page_count * page_size;
            uint64_t swapouts = (uint64_t)vm.swapouts;

            // Only query vm.swapusage when swapouts changed, on --status, if baseline is uninitialized, or every 8 ticks while swap > 0 to ratchet baseline down.
            int swap_ok = 1;
            if (once || min_swap_used == UINT64_MAX || swapouts != prev_swapouts || (min_swap_used > 0 && (tick & 7U) == 0)) {
                swap_ok = (get_swap_used(&swap_used) == 0);
            }

            // Only query kern.memorystatus_level when total pages (including file cache) reach fast_poll_bytes or on --status.
            int mem_level = (once || total_cached >= fast_poll_bytes) ? get_memorystatus_level() : 100;
            if (once && (!swap_ok || mem_level < 0)) {
                fprintf(stderr, "memguard: %s unavailable\n", !swap_ok ? "swap usage" : "memory pressure");
                return 1;
            }
            if (mem_level < 0) mem_level = 100; // Preserve daemon behavior if the pressure query fails.
            double sys_pct = (double)sys_used / (double)memsize;
            double level_pct = (100.0 - (double)mem_level) / 100.0;
            double effective_ram_pct = sys_pct > level_pct ? sys_pct : level_pct;

            const char *reason = NULL;
            int trig = should_trigger(effective_ram_pct, sys_used, memsize,
                                      g_conf.max_ram_fraction, g_conf.panic_ram_fraction,
                                      swap_used, min_swap_used, max_swap_allowance,
                                      swap_burst_floor, swap_ok ? swapouts : prev_swapouts, prev_swapouts, &reason);
            uint64_t prev_baseline = min_swap_used == UINT64_MAX ? swap_used : min_swap_used;
            if (swap_ok) {
                if (swap_used < min_swap_used ||
                    (trig == TRIG_NONE && swapouts != prev_swapouts && sys_used < memsize / 2 && max_swap_allowance == 0)) {
                    min_swap_used = swap_used;
                }
                prev_swapouts = swapouts;
            }

            // Only walk the process table when a threshold is reached or --status is invoked.
            if (once || trig != TRIG_NONE) {
                int got = proc_listpids(PROC_UID_ONLY, (uint32_t)self_uid, g_pids, (int)sizeof(g_pids));
                if (once && (got <= 0 || got >= (int)sizeof(g_pids))) {
                    fprintf(stderr, "memguard: process list %s\n", got >= (int)sizeof(g_pids) ? "truncated" : "unavailable");
                    return 1;
                }
                if (got > 0) {
                    int n = got / (int)sizeof(pid_t);
                    uint64_t max_unprot_fp = 0, max_soft_fp = 0;
                    uint64_t max_unprot_start = 0, max_soft_start = 0;
                    pid_t max_unprot_pid = 0, max_soft_pid = 0;
                    char max_unprot_name[MAX_NAME_LEN] = {0};
                    char max_soft_name[MAX_NAME_LEN] = {0};
                    time_t now = time(NULL);
                    struct timespec mono_now = {0, 0};
                    clock_gettime(CLOCK_MONOTONIC, &mono_now);

                    for (int i = 0; i < n; i++) {
                        pid_t pid = g_pids[i];
                        if (pid <= 1 || pid == self_pid) continue;
                        int in_cooldown = 0;
                        for (int c = 0; c < COOLDOWN_SLOTS; c++) {
                            if (killed_pids[c] == pid) {
                                double elapsed = (double)(mono_now.tv_sec - killed_ts[c].tv_sec) +
                                                 (double)(mono_now.tv_nsec - killed_ts[c].tv_nsec) * 1e-9;
                                double cooldown = dry_run && g_conf.kill_cooldown_s < 1.0 ? 1.0 : g_conf.kill_cooldown_s;
                                if (elapsed < cooldown) {
                                    in_cooldown = 1;
                                    break;
                                }
                            }
                        }
                        if (in_cooldown) continue;
                        struct rusage_info_v0 ri;
                        if (proc_pid_rusage(pid, RUSAGE_INFO_V0, (rusage_info_t *)&ri) == 0) {
                            if (ri.ri_phys_footprint <= max_unprot_fp && ri.ri_phys_footprint <= max_soft_fp) continue;
                            char name[MAX_NAME_LEN];
                            if (proc_name(pid, name, sizeof(name)) <= 0) continue;
                            int tier = protection_tier(name);
                            if (tier == PROT_NONE && ri.ri_phys_footprint > max_unprot_fp) {
                                max_unprot_fp = ri.ri_phys_footprint;
                                max_unprot_start = ri.ri_proc_start_abstime;
                                max_unprot_pid = pid;
                                strlcpy(max_unprot_name, name, sizeof(max_unprot_name));
                            } else if (tier == PROT_SOFT && ri.ri_phys_footprint > max_soft_fp) {
                                max_soft_fp = ri.ri_phys_footprint;
                                max_soft_start = ri.ri_proc_start_abstime;
                                max_soft_pid = pid;
                                strlcpy(max_soft_name, name, sizeof(max_soft_name));
                            }
                        }
                    }

                    if (once) {
                        const char *no_color = getenv("NO_COLOR");
                        int color = isatty(STDOUT_FILENO) && !(no_color && *no_color);
                        const char *reset = color ? "\033[0m" : "";
                        const char *state_color = color ? (dpid > 0 ? "\033[32m" : "\033[33m") : "";
                        const char *ram_color = color ? (sys_pct >= g_conf.max_ram_fraction ? "\033[31m" :
                                                       sys_pct >= g_conf.fast_poll_ram_fraction ? "\033[33m" : "") : "";
                        const char *pressure_color = color ? (level_pct >= g_conf.max_ram_fraction ? "\033[31m" :
                                                            level_pct >= g_conf.fast_poll_ram_fraction ? "\033[33m" : "") : "";
                        printf("memguard — %s%s%s", state_color, selftest ? "self-test" :
                               dpid > 0 ? "running" : dpid == 0 ? "stopped" : "not loaded", reset);
                        if (!selftest && dpid > 0) printf(" · PID %d", dpid);
                        printf("\n\nMemory\n"
                               "  RAM used        %s%.2f / %.2f GiB · %.1f%%%s\n"
                               "  Pressure        %s%d%% available%s\n"
                               "  Swap used       %.2f GiB\n\n"
                               "Config on disk\n"
                               "  RAM thresholds  fast poll %.1f%% · kill %.1f%% · panic %.1f%%\n"
                               "  Poll interval   normal %.0f ms · fast %.0f ms\n"
                               "  Victim minimum  %.2f GiB\n"
                               "  Swap allowance  %.2f GiB growth · burst floor %.0f MiB\n"
                               "  Cooldown        %.2f s\n"
                               "  Protection      %d rules\n"
                               "  File            ",
                               ram_color, sys_used / GIB_BYTES, memsize / GIB_BYTES, 100.0 * sys_pct, reset,
                               pressure_color, mem_level, reset, swap_used / GIB_BYTES,
                               100.0 * g_conf.fast_poll_ram_fraction, 100.0 * g_conf.max_ram_fraction,
                               100.0 * g_conf.panic_ram_fraction, g_conf.poll_interval_ms, g_conf.fast_poll_interval_ms,
                               g_conf.min_victim_gib, g_conf.max_swap_gib, g_conf.swap_burst_floor_mib,
                               g_conf.kill_cooldown_s, g_conf.protected_count);
                        status_text(conf_path);
                        puts("\n\nLargest observed processes (eligibility uses config on disk)");
                        status_process("Unprotected", max_unprot_pid, max_unprot_name, max_unprot_fp, min_victim_bytes, 0);
                        status_process("Soft-protected", max_soft_pid, max_soft_name, max_soft_fp, min_victim_bytes, 1);
                        puts("\nSnapshot only; daemon loaded config, swap baseline and cooldowns are not queried.");
                        if (fflush(stdout) == EOF || ferror(stdout)) {
                            perror("memguard: status output");
                            return 1;
                        }
                        return 0;
                    }

                    char ts[32];
                    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S%z", localtime(&now));

                    pid_t target_pid = 0;
                    uint64_t target_start = 0;
                    const char *target_name = NULL;
                    int target_expected_tier = PROT_NONE;
                    if (max_unprot_pid > 1 && max_unprot_fp >= min_victim_bytes) {
                        target_pid = max_unprot_pid;
                        target_start = max_unprot_start;
                        target_name = max_unprot_name;
                        target_expected_tier = PROT_NONE;
                    } else if (trig == TRIG_PANIC && max_soft_pid > 1 && max_soft_fp >= min_victim_bytes) {
                        target_pid = max_soft_pid;
                        target_start = max_soft_start;
                        target_name = max_soft_name;
                        target_expected_tier = PROT_SOFT;
                    }

                    int did_kill = 0;
                    if (target_pid > 1) {
                        char verify_name[MAX_NAME_LEN] = {0};
                        struct rusage_info_v0 verify_ri;
                        if (verify_target(target_pid, target_start, target_name, target_expected_tier,
                                          min_victim_bytes, verify_name, &verify_ri)) {
                            // shortcut: identity/name checks cannot bind kill atomically; use a stable OS handle if macOS adds one.
                            int rc = dry_run ? 0 : kill(target_pid, SIGKILL);
                            int kill_errno = rc == 0 ? 0 : errno;
                            double target_gib = verify_ri.ri_phys_footprint / GIB_BYTES;
                            fprintf(stderr, "[%s] %s (%s) pid=%d (%s) footprint=%.2f GiB | sys_used=%.2f GiB (%.1f%%) memstatus_avail=%d%% swap=%.2f->%.2f GiB rc=%d errno=%d\n",
                                    ts, dry_run ? "WOULD_KILL" : rc == 0 ? "KILLED" : "KILL_FAILED", reason, target_pid, verify_name,
                                    target_gib, sys_used / GIB_BYTES, 100.0 * sys_pct, mem_level,
                                    prev_baseline / GIB_BYTES, swap_used / GIB_BYTES, rc, kill_errno);
                            fflush(stderr);
                            if (rc == 0) {
                                did_kill = !dry_run;
                                if (!dry_run) notify_kill(reason, verify_name, target_pid, target_gib);
                                killed_pids[killed_idx % COOLDOWN_SLOTS] = target_pid;
                                killed_ts[killed_idx % COOLDOWN_SLOTS] = mono_now;
                                killed_idx++;

                                for (int w = 0; !dry_run && w < 8; w++) {
                                    if (wait_poll(500000, &wait_mask) != 0) return 1;
                                    if (g_reload) break;
                                    struct rusage_info_v0 wri;
                                    if (w >= 1 && ((kill(target_pid, 0) != 0 && errno == ESRCH) ||
                                                   proc_pid_rusage(target_pid, RUSAGE_INFO_V0, (rusage_info_t *)&wri) != 0 ||
                                                   wri.ri_proc_start_abstime != target_start ||
                                                   wri.ri_phys_footprint < min_victim_bytes)) break;
                                }
                            }
                        }
                    } else if (now - last_skip_log_time >= kill_cooldown_s) {
                        fprintf(stderr, "[%s] SKIPPED (%s): largest unprotected pid=%d (%s, %.2f GiB) < min_victim_gib=%.2f GiB (largest soft-protected: pid=%d %s %.2f GiB) | sys_used=%.2f GiB (%.1f%%) memstatus_avail=%d%% swap=%.2f->%.2f GiB\n",
                                ts, reason, max_unprot_pid, max_unprot_name, max_unprot_fp / GIB_BYTES,
                                g_conf.min_victim_gib, max_soft_pid, max_soft_name, max_soft_fp / GIB_BYTES,
                                sys_used / GIB_BYTES, 100.0 * sys_pct, mem_level,
                                prev_baseline / GIB_BYTES, swap_used / GIB_BYTES);
                        fflush(stderr);
                        last_skip_log_time = now;
                    }
                    if (did_kill) {
                        if (get_swap_used(&swap_used) == 0) min_swap_used = swap_used;
                        if (host_statistics64(host_port, HOST_VM_INFO64, (host_info64_t)&vm, &count) == KERN_SUCCESS) {
                            prev_swapouts = (uint64_t)vm.swapouts;
                        }
                    } else if (swap_ok && strcmp(reason, "SWAP_LIMIT") == 0) {
                        min_swap_used = swap_used;
                    }
                    if (wait_poll(fast_poll_us, &wait_mask) != 0) return 1;
                    continue;
                }
            }
            if (once) return 0;
            if (wait_poll(effective_ram_pct >= g_conf.fast_poll_ram_fraction ? fast_poll_us : poll_us,
                          &wait_mask) != 0) return 1;
            continue;
        }
        if (once) {
            fprintf(stderr, "memguard: VM statistics unavailable\n");
            return 1;
        }
        if (wait_poll(poll_us, &wait_mask) != 0) return 1;
    }
}
