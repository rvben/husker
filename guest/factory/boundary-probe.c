/* Operator-owned, unprivileged factory job probe. No host execution fallback.
 * Only documentation IPs are contacted, and only their kernel route failures
 * count as denial. Refused connections/timeouts are inconclusive failures.
 * This subset is NOT a full promotion or host-service isolation proof. */
#include <stdio.h>
#include <string.h>
#ifdef __linux__
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static unsigned checks, failures;
static int factory_membership(void) {
    FILE *file = fopen("/proc/self/cgroup","r");
    if (!file) return 0;
    char line[256], extra[2];
    int read = fgets(line,sizeof(line),file) != NULL;
    int additional = fgets(extra,sizeof(extra),file) != NULL;
    fclose(file);
    const char *prefix = "0::/husker-check-";
    if (!read || additional || strncmp(line,prefix,strlen(prefix))) return 0;
    char *id = line + strlen(prefix);
    if (strlen(id) < 39) return 0;
    for (unsigned i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (id[i] != '-') return 0;
        } else if (!((id[i] >= '0' && id[i] <= '9') || (id[i] >= 'a' && id[i] <= 'f'))) return 0;
    }
    if (id[36] != '-' || id[37] < '0' || id[37] > '9') return 0;
    char *end; unsigned long index = strtoul(id+37,&end,10);
    return index < 32 && !strcmp(end,"\n");
}
static void check(const char *name, int ok, int error) {
    checks++; failures += !ok;
    printf("{\"type\":\"check\",\"name\":\"%s\",\"ok\":%s,\"errno\":%d}\n",
           name, ok ? "true" : "false", error);
}
static void protected_path(const char *name, const char *path) {
    int fd = open(path, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    int error = fd < 0 ? errno : 0;
    if (fd >= 0) close(fd); /* Never truncate or modify an unexpectedly writable file. */
    check(name, fd < 0 && (error == EACCES || error == EPERM || error == EROFS), error);
}
static int status_policy(void) {
    FILE *file = fopen("/proc/self/status", "r");
    if (!file) return 0;
    char line[512]; unsigned found = 0; int ok = 1;
    while (fgets(line, sizeof(line), file)) {
        const char *fields[] = {"CapEff:", "CapPrm:", "CapAmb:", "NoNewPrivs:"};
        for (unsigned i = 0; i < 4; i++) {
            if (!strncmp(line, fields[i], strlen(fields[i]))) {
                char *end; unsigned long long value = strtoull(line + strlen(fields[i]), &end, i == 3 ? 10 : 16);
                if (end == line + strlen(fields[i]) || value != (i == 3 ? 1ULL : 0ULL)) ok = 0;
                found |= 1U << i;
            }
        }
    }
    fclose(file); return ok && found == 15;
}
/* CONFIG_IPV6_SIT creates an inert fallback tunnel even without any VM NIC.
 * Accept only that exact kernel device, down and without an IPv4 address. */
static int inert_sit(const char *name) {
    if (strcmp(name,"sit0")) return 0;
    FILE *type = fopen("/sys/class/net/sit0/type","r");
    unsigned hardware = 0;
    int parsed = type && fscanf(type,"%u",&hardware) == 1;
    if (type) fclose(type);
    if (!parsed || hardware != 776) return 0; /* ARPHRD_SIT */
    int fd = socket(AF_INET,SOCK_DGRAM | SOCK_CLOEXEC,0);
    if (fd < 0) return 0;
    struct ifreq request; memset(&request,0,sizeof(request));
    memcpy(request.ifr_name,"sit0",5);
    int down = ioctl(fd,SIOCGIFFLAGS,&request) == 0 && !(request.ifr_flags & IFF_UP);
    int missing_address = ioctl(fd,SIOCGIFADDR,&request) < 0 && errno == EADDRNOTAVAIL;
    close(fd);
    return down && missing_address;
}
static int no_interfaces(void) {
    DIR *directory = opendir("/sys/class/net");
    if (!directory) return 0;
    struct dirent *entry; int ok = 1, loopback = 0;
    while ((entry = readdir(directory))) {
        if (!strcmp(entry->d_name,".") || !strcmp(entry->d_name,"..")) continue;
        if (!strcmp(entry->d_name,"lo")) loopback = 1;
        else if (!inert_sit(entry->d_name)) ok = 0;
    }
    closedir(directory); return ok && loopback;
}
static int no_shared_filesystems(void) {
    FILE *file = fopen("/proc/self/mountinfo", "r");
    if (!file) return 0;
    char line[4096]; unsigned lines = 0; int ok = 1;
    while (fgets(line, sizeof(line), file)) {
        if (++lines > 256 || !strchr(line,'\n')) { ok = 0; break; }
        char *separator = strstr(line," - ");
        if (!separator) { ok = 0; break; }
        separator += 3;
        const char *types[] = {"virtiofs ","9p ","nfs ","nfs4 ","cifs "};
        for (unsigned i = 0; i < 5; i++) if (!strncmp(separator,types[i],strlen(types[i]))) ok = 0;
    }
    if (ferror(file)) ok = 0;
    fclose(file); return ok && lines;
}
static int route_denied(int error) {
    return error == ENETUNREACH || error == EHOSTUNREACH || error == EACCES || error == EPERM;
}
static void network_probe(const char *name, int family, const char *address, int dns) {
    int fd = socket(family, (dns ? SOCK_DGRAM : SOCK_STREAM) | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) { check(name,0,errno); return; } /* Unsupported is not a proof. */
    struct sockaddr_storage storage; memset(&storage,0,sizeof(storage)); socklen_t length;
    if (family == AF_INET) {
        struct sockaddr_in *target = (struct sockaddr_in *)&storage;
        target->sin_family = AF_INET; target->sin_port = htons(dns ? 53 : 9);
        if (inet_pton(family,address,&target->sin_addr) != 1) { close(fd); check(name,0,EINVAL); return; }
        length = sizeof(*target);
    } else {
        struct sockaddr_in6 *target = (struct sockaddr_in6 *)&storage;
        target->sin6_family = AF_INET6; target->sin6_port = htons(9);
        if (inet_pton(family,address,&target->sin6_addr) != 1) { close(fd); check(name,0,EINVAL); return; }
        length = sizeof(*target);
    }
    /* A bounded DNS A query for example.invalid, never a personal identifier. */
    const unsigned char query[] = {0x48,0x4b,1,0,0,1,0,0,0,0,0,0,7,'e','x','a','m','p','l','e',7,'i','n','v','a','l','i','d',0,0,1,0,1};
    int result = dns ? (int)sendto(fd,query,sizeof(query),0,(struct sockaddr *)&storage,length)
                     : connect(fd,(struct sockaddr *)&storage,length);
    int error = result < 0 ? errno : 0;
    /* An IPv6 stack with no local addresses rejects connect before routing.
     * This is a kernel denial, not a remote refusal or elapsed timeout. */
    int denied = route_denied(error) || (family == AF_INET6 && error == EADDRNOTAVAIL);
    close(fd); check(name,result < 0 && denied,error);
}
int main(int argc, char **argv) {
    if (argc != 2 || strcmp(argv[1],"--factory-boundary") || geteuid() != 1000 || getegid() != 1000 || !factory_membership()) {
        fputs("requires an explicit unprivileged Linux factory job (UID/GID 1000)\n",stderr); return 2;
    }
    check("uid-gid-groups",getuid() == 1000 && getgid() == 1000 && getgroups(0,NULL) == 0,0);
    check("capabilities-and-no-new-privileges",status_policy(),0);
    check("no-external-network-interfaces",no_interfaces(),0);
    check("no-shared-filesystem-types",no_shared_filesystems(),0);
    const char *variables[] = {"SSH_AUTH_SOCK","HUSKER_TOKEN","OPENAI_API_KEY","ANTHROPIC_API_KEY","AWS_ACCESS_KEY_ID","AWS_SECRET_ACCESS_KEY"};
    int clean = 1;
    for (unsigned i = 0; i < sizeof(variables)/sizeof(variables[0]); i++) if (getenv(variables[i])) clean = 0;
    check("credential-environment-absent",clean,0);
    protected_path("frozen-source-not-writable","/workspace/frozen-sentinel");
    protected_path("acceptance-not-writable","/acceptance/frozen-sentinel");
    /* Reading management identity must also be denied, not merely writing. */
    int identity = open("/run/husker-job/identity.json",O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    int error = identity < 0 ? errno : 0;
    if (identity >= 0) close(identity);
    check("management-identity-not-readable",identity < 0 && (error == EACCES || error == EPERM),error);
    network_probe("ipv4-kernel-route-denied",AF_INET,"192.0.2.1",0);
    network_probe("ipv6-kernel-route-denied",AF_INET6,"2001:db8::1",0);
    network_probe("dns-udp-kernel-route-denied",AF_INET,"192.0.2.53",1);
    printf("{\"type\":\"summary\",\"scope\":\"offline-job-subset-v1\",\"checks\":%u,\"failed\":%u}\n",checks,failures);
    return failures ? 1 : 0;
}
#else
int main(void) {
    fputs("factory boundary probe requires a Linux guest; refusing host execution\n",stderr);
    return 2;
}
#endif
