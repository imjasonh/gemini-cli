/*
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 *
 * landlock-helper: unprivileged filesystem sandbox using Linux Landlock.
 *
 * Usage:
 *   landlock-helper [--ro PATH]... [--rw PATH]... [--rx PATH]... \
 *                   [--seccomp FILE] -- command [args...]
 *
 * Requires Linux kernel 5.13+ with Landlock LSM enabled.
 * Build: gcc -static -O2 -o landlock-helper landlock-helper.c
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/prctl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <unistd.h>

/* --- Landlock constants (inline to avoid kernel header dependency) --- */

#ifndef LANDLOCK_CREATE_RULESET
#define LANDLOCK_CREATE_RULESET 444
#endif
#ifndef LANDLOCK_ADD_RULE
#define LANDLOCK_ADD_RULE 445
#endif
#ifndef LANDLOCK_RESTRICT_SELF
#define LANDLOCK_RESTRICT_SELF 446
#endif

/* Landlock access flags for files */
#define LANDLOCK_ACCESS_FS_EXECUTE          (1ULL << 0)
#define LANDLOCK_ACCESS_FS_WRITE_FILE       (1ULL << 1)
#define LANDLOCK_ACCESS_FS_READ_FILE        (1ULL << 2)
#define LANDLOCK_ACCESS_FS_READ_DIR         (1ULL << 3)
#define LANDLOCK_ACCESS_FS_REMOVE_DIR       (1ULL << 4)
#define LANDLOCK_ACCESS_FS_REMOVE_FILE      (1ULL << 5)
#define LANDLOCK_ACCESS_FS_MAKE_CHAR        (1ULL << 6)
#define LANDLOCK_ACCESS_FS_MAKE_DIR         (1ULL << 7)
#define LANDLOCK_ACCESS_FS_MAKE_REG         (1ULL << 8)
#define LANDLOCK_ACCESS_FS_MAKE_SOCK        (1ULL << 9)
#define LANDLOCK_ACCESS_FS_MAKE_FIFO        (1ULL << 10)
#define LANDLOCK_ACCESS_FS_MAKE_BLOCK       (1ULL << 11)
#define LANDLOCK_ACCESS_FS_MAKE_SYM         (1ULL << 12)
#define LANDLOCK_ACCESS_FS_REFER            (1ULL << 13)
#define LANDLOCK_ACCESS_FS_TRUNCATE         (1ULL << 14)

/* Rule type */
#define LANDLOCK_RULE_PATH_BENEATH 1

/* All ABI v1 access rights (the base set) */
#define ACCESS_ABI_V1 ( \
    LANDLOCK_ACCESS_FS_EXECUTE       | \
    LANDLOCK_ACCESS_FS_WRITE_FILE    | \
    LANDLOCK_ACCESS_FS_READ_FILE     | \
    LANDLOCK_ACCESS_FS_READ_DIR      | \
    LANDLOCK_ACCESS_FS_REMOVE_DIR    | \
    LANDLOCK_ACCESS_FS_REMOVE_FILE   | \
    LANDLOCK_ACCESS_FS_MAKE_CHAR     | \
    LANDLOCK_ACCESS_FS_MAKE_DIR      | \
    LANDLOCK_ACCESS_FS_MAKE_REG      | \
    LANDLOCK_ACCESS_FS_MAKE_SOCK     | \
    LANDLOCK_ACCESS_FS_MAKE_FIFO     | \
    LANDLOCK_ACCESS_FS_MAKE_BLOCK    | \
    LANDLOCK_ACCESS_FS_MAKE_SYM)

/* ABI v2 adds REFER */
#define ACCESS_ABI_V2 (ACCESS_ABI_V1 | LANDLOCK_ACCESS_FS_REFER)

/* ABI v3 adds TRUNCATE */
#define ACCESS_ABI_V3 (ACCESS_ABI_V2 | LANDLOCK_ACCESS_FS_TRUNCATE)

/* Convenience groups */
#define ACCESS_RO (LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR)
#define ACCESS_RX (ACCESS_RO | LANDLOCK_ACCESS_FS_EXECUTE)

/* Landlock structures */
struct landlock_ruleset_attr {
    uint64_t handled_access_fs;
    uint64_t handled_access_net; /* ABI v4+, unused here */
};

struct landlock_path_beneath_attr {
    uint64_t allowed_access;
    int32_t  parent_fd;
};

/* Seccomp constants for loading BPF */
#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 1
#endif

struct sock_fprog {
    uint16_t len;
    void    *filter;
};

/* --- Syscall wrappers --- */

static inline int landlock_create_ruleset(
    const struct landlock_ruleset_attr *attr, size_t size, uint32_t flags)
{
    return (int)syscall(LANDLOCK_CREATE_RULESET, attr, size, flags);
}

static inline int landlock_add_rule(
    int ruleset_fd, int rule_type, const void *rule_attr, uint32_t flags)
{
    return (int)syscall(LANDLOCK_ADD_RULE, ruleset_fd, rule_type, rule_attr, flags);
}

static inline int landlock_restrict_self(int ruleset_fd, uint32_t flags)
{
    return (int)syscall(LANDLOCK_RESTRICT_SELF, ruleset_fd, flags);
}

/* --- Detect highest supported ABI version --- */

static int detect_abi_version(void)
{
    /* LANDLOCK_CREATE_RULESET with NULL attr and size 0 returns the ABI version */
    int abi = (int)syscall(LANDLOCK_CREATE_RULESET, NULL, 0, 1 << 0);
    if (abi < 0) {
        return 0; /* Landlock not supported */
    }
    return abi;
}

static uint64_t access_mask_for_abi(int abi)
{
    if (abi >= 3) return ACCESS_ABI_V3;
    if (abi >= 2) return ACCESS_ABI_V2;
    return ACCESS_ABI_V1;
}

/* --- Path rule helpers --- */

#define MAX_PATHS 256

struct path_entry {
    const char *path;
    uint64_t    access;
    int         fatal;  /* fail if path cannot be opened */
};

static int add_path_rule(int ruleset_fd, const char *path, uint64_t access,
                         int fatal_on_missing)
{
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0) {
        if (fatal_on_missing) {
            fprintf(stderr, "landlock-helper: error: cannot open '%s': %s\n",
                    path, strerror(errno));
            return -1;
        }
        fprintf(stderr, "landlock-helper: warning: cannot open '%s': %s (skipped)\n",
                path, strerror(errno));
        return 0;
    }

    struct landlock_path_beneath_attr attr = {
        .allowed_access = access,
        .parent_fd = fd,
    };

    int ret = landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &attr, 0);
    close(fd);

    if (ret < 0) {
        fprintf(stderr, "landlock-helper: error: landlock_add_rule failed for '%s': %s\n",
                path, strerror(errno));
        return -1;
    }
    return 0;
}

/* --- Seccomp BPF loader --- */

static int load_seccomp_file(const char *filepath)
{
    int fd = open(filepath, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "landlock-helper: cannot open seccomp file '%s': %s\n",
                filepath, strerror(errno));
        return -1;
    }

    /* Read entire file */
    struct stat st;
    if (fstat(fd, &st) < 0) {
        fprintf(stderr, "landlock-helper: fstat failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    void *buf = malloc((size_t)st.st_size);
    if (!buf) {
        fprintf(stderr, "landlock-helper: malloc failed\n");
        close(fd);
        return -1;
    }

    ssize_t n = read(fd, buf, (size_t)st.st_size);
    close(fd);
    if (n != st.st_size) {
        fprintf(stderr, "landlock-helper: short read on seccomp file\n");
        free(buf);
        return -1;
    }

    /* Each sock_filter is 8 bytes */
    uint16_t num_insns = (uint16_t)(st.st_size / 8);
    struct sock_fprog prog = {
        .len = num_insns,
        .filter = buf,
    };

    int ret = (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog);
    free(buf);

    if (ret < 0) {
        fprintf(stderr, "landlock-helper: seccomp load failed: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

/* --- Usage --- */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [--ro PATH]... [--rw PATH]... [--rx PATH]... "
        "[--seccomp FILE] -- command [args...]\n", prog);
    exit(1);
}

/* --- Main --- */

int main(int argc, char **argv)
{
    struct path_entry paths[MAX_PATHS];
    int num_paths = 0;
    const char *seccomp_file = NULL;
    int cmd_start = -1;

    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            cmd_start = i + 1;
            break;
        } else if (strcmp(argv[i], "--ro") == 0) {
            if (++i >= argc) usage(argv[0]);
            if (num_paths >= MAX_PATHS) {
                fprintf(stderr, "landlock-helper: too many paths\n");
                return 1;
            }
            paths[num_paths].path = argv[i];
            paths[num_paths].access = ACCESS_RO;
            paths[num_paths].fatal = 0;
            num_paths++;
        } else if (strcmp(argv[i], "--rw") == 0) {
            if (++i >= argc) usage(argv[0]);
            if (num_paths >= MAX_PATHS) {
                fprintf(stderr, "landlock-helper: too many paths\n");
                return 1;
            }
            paths[num_paths].path = argv[i];
            paths[num_paths].access = 0; /* placeholder, set after ABI detection */
            paths[num_paths].fatal = 1;  /* writable paths must exist */
            num_paths++;
        } else if (strcmp(argv[i], "--rx") == 0) {
            if (++i >= argc) usage(argv[0]);
            if (num_paths >= MAX_PATHS) {
                fprintf(stderr, "landlock-helper: too many paths\n");
                return 1;
            }
            paths[num_paths].path = argv[i];
            paths[num_paths].access = ACCESS_RX;
            paths[num_paths].fatal = 0;
            num_paths++;
        } else if (strcmp(argv[i], "--seccomp") == 0) {
            if (++i >= argc) usage(argv[0]);
            seccomp_file = argv[i];
        } else {
            fprintf(stderr, "landlock-helper: unknown option '%s'\n", argv[i]);
            usage(argv[0]);
        }
    }

    if (cmd_start < 0 || cmd_start >= argc) {
        fprintf(stderr, "landlock-helper: missing command after '--'\n");
        usage(argv[0]);
    }

    /* Detect Landlock ABI version */
    int abi = detect_abi_version();
    if (abi <= 0) {
        fprintf(stderr, "landlock-helper: Landlock is not supported by this kernel\n");
        return 1;
    }

    uint64_t all_access = access_mask_for_abi(abi);

    /* Fill in --rw access (full access for the ABI version) */
    for (int i = 0; i < num_paths; i++) {
        if (paths[i].access == 0) {
            paths[i].access = all_access;
        }
    }

    /* Create ruleset */
    struct landlock_ruleset_attr ruleset_attr = {
        .handled_access_fs = all_access,
    };

    int ruleset_fd = landlock_create_ruleset(
        &ruleset_attr, sizeof(ruleset_attr), 0);
    if (ruleset_fd < 0) {
        fprintf(stderr, "landlock-helper: landlock_create_ruleset failed: %s\n",
                strerror(errno));
        return 1;
    }

    /* Add rules for each path */
    for (int i = 0; i < num_paths; i++) {
        if (add_path_rule(ruleset_fd, paths[i].path, paths[i].access,
                          paths[i].fatal) < 0) {
            close(ruleset_fd);
            return 1;
        }
    }

    /* Prevent gaining new privileges (required for both Landlock and seccomp) */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        fprintf(stderr, "landlock-helper: prctl(PR_SET_NO_NEW_PRIVS) failed: %s\n",
                strerror(errno));
        close(ruleset_fd);
        return 1;
    }

    /* Load seccomp BPF filter before restricting filesystem access */
    if (seccomp_file) {
        if (load_seccomp_file(seccomp_file) < 0) {
            close(ruleset_fd);
            return 1;
        }
    }

    /* Enforce the Landlock ruleset */
    if (landlock_restrict_self(ruleset_fd, 0) < 0) {
        fprintf(stderr, "landlock-helper: landlock_restrict_self failed: %s\n",
                strerror(errno));
        close(ruleset_fd);
        return 1;
    }

    close(ruleset_fd);

    /* Execute the command */
    execvp(argv[cmd_start], &argv[cmd_start]);
    fprintf(stderr, "landlock-helper: execvp '%s' failed: %s\n",
            argv[cmd_start], strerror(errno));
    return 127;
}
