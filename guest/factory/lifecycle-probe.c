/* Trusted intentional-fault probe. Compile for the guest; never run on a host.
 * Descendants escape the process group and ignore SIGTERM. The runner must use
 * its owned cgroup (normal failure/timeout), or destroy the VM (cancellation).
 */
#include <stdio.h>
#include <string.h>
#ifdef __linux__
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

static int factory_policy(void) {
    if (getuid() != 1000 || getgid() != 1000 || getgroups(0, NULL) != 0) return 0;
    FILE *file = fopen("/proc/self/cgroup", "r");
    if (!file) return 0;
    char line[256], extra[2];
    int found = fgets(line, sizeof(line), file) != NULL;
    int more = fgets(extra, sizeof(extra), file) != NULL;
    fclose(file);
    const char *prefix = "0::/husker-check-";
    if (!found || more || strncmp(line, prefix, strlen(prefix))) return 0;
    char *id = line + strlen(prefix);
    if (strlen(id) < 39) return 0;
    for (unsigned i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (id[i] != '-') return 0;
        } else if (!((id[i] >= '0' && id[i] <= '9') || (id[i] >= 'a' && id[i] <= 'f'))) return 0;
    }
    if (id[36] != '-' || id[37] < '0' || id[37] > '9') return 0;
    char *end;
    unsigned long index = strtoul(id + 37, &end, 10);
    if (index >= 32 || strcmp(end, "\n")) return 0;
    file = fopen("/proc/self/status", "r");
    if (!file) return 0;
    unsigned fields = 0;
    int ok = 1;
    while (fgets(line, sizeof(line), file)) {
        const char *names[] = {"CapEff:", "CapPrm:", "CapAmb:", "NoNewPrivs:"};
        for (unsigned i = 0; i < 4; i++) {
            if (!strncmp(line, names[i], strlen(names[i]))) {
                unsigned long long value = strtoull(line + strlen(names[i]), &end, i == 3 ? 10 : 16);
                if (end == line + strlen(names[i]) || value != (i == 3 ? 1ULL : 0ULL)) ok = 0;
                fields |= 1U << i;
            }
        }
    }
    fclose(file);
    return ok && fields == 15;
}
static int read_counter(const char *directory, const char *name, int events, unsigned long long *value) {
    char path[256];
    int length = snprintf(path, sizeof(path), "%s/%s", directory, name);
    if (length < 0 || (size_t)length >= sizeof(path)) return 0;
    FILE *file = fopen(path, "r");
    if (!file) return 0;
    char key[32];
    int count = events ? fscanf(file, "%31s %llu", key, value) : fscanf(file, "%llu", value);
    int ok = count == (events ? 2 : 1) && (!events || !strcmp(key, "max"));
    fclose(file);
    return ok;
}
static void hold(void) {
    for (;;) pause();
}
static int pids_pressure(void) {
    FILE *file = fopen("/proc/self/cgroup", "r");
    if (!file) return 3;
    char membership[128];
    if (!fgets(membership, sizeof(membership), file)) { fclose(file); return 3; }
    fclose(file);
    if (strncmp(membership, "0::/husker-check-", strlen("0::/husker-check-"))) return 3;
    membership[strcspn(membership, "\n")] = 0;
    char directory[256];
    int length = snprintf(directory, sizeof(directory), "/sys/fs/cgroup%s", membership + 3);
    if (length < 0 || (size_t)length >= sizeof(directory)) return 3;
    unsigned long long maximum, before, after, current;
    if (!read_counter(directory, "pids.max", 0, &maximum) || maximum != 64
        || !read_counter(directory, "pids.current", 0, &current) || current != 1
        || !read_counter(directory, "pids.events", 1, &before)) return 3;
    unsigned spawned = 0;
    int error = 0;
    for (unsigned attempt = 0; attempt < 64; attempt++) {
        pid_t child = fork();
        if (child == 0) hold();
        if (child < 0) { error = errno; break; }
        spawned++;
    }
    if (spawned != 63 || error != EAGAIN
        || !read_counter(directory, "pids.current", 0, &current) || current != 64
        || !read_counter(directory, "pids.events", 1, &after) || after <= before) return 3;
    puts("{\"type\":\"limit\",\"scope\":\"pids-pressure-v1\",\"spawned\":63,\"pids_max\":64,\"pids_current\":64,\"limit_event_increased\":true,\"fork_errno\":11}");
    return fflush(stdout) ? 3 : 0;
}
int main(int argc, char **argv) {
    if (argc != 2 || (strcmp(argv[1], "--fail-family") && strcmp(argv[1], "--hold-family") && strcmp(argv[1], "--pids-pressure"))) return 2;
    if (!factory_policy()) {
        fputs("factory lifecycle probe requires an unprivileged owned guest cgroup; refusing host execution\n", stderr);
        return 2;
    }
    if (!strcmp(argv[1], "--pids-pressure")) return pids_pressure();
    int ready[2];
    if (pipe(ready)) return 3;
    pid_t child = fork();
    if (child < 0) return 3;
    if (child == 0) {
        close(ready[0]);
        if (setsid() < 0 || signal(SIGTERM, SIG_IGN) == SIG_ERR) _exit(3);
        pid_t grandchild = fork();
        if (grandchild < 0) _exit(3);
        if (grandchild == 0) {
            if (setsid() < 0) _exit(3);
            char byte = 'R';
            if (write(ready[1], &byte, 1) != 1) _exit(3);
            close(ready[1]);
            hold();
        }
        close(ready[1]);
        hold();
    }
    close(ready[1]);
    char byte = 0;
    ssize_t count;
    do { count = read(ready[0], &byte, 1); } while (count < 0 && errno == EINTR);
    close(ready[0]);
    if (count != 1 || byte != 'R') return 3;
    puts("{\"type\":\"ready\",\"scope\":\"escaped-family-v1\",\"descendants\":2,\"setsid\":true,\"ignore_sigterm\":true}");
    if (fflush(stdout)) return 3;
    if (!strcmp(argv[1], "--fail-family")) return 7;
    hold();
    return 3;
}
#else
int main(void) {
    fputs("factory lifecycle probe requires a Linux guest; refusing host execution\n", stderr);
    return 2;
}
#endif
