#define _GNU_SOURCE
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Weak, so the object also links into configure's throwaway test programs. */
extern bool xemu_settings_load(void) __attribute__((weak));
extern void xemu_settings_set_path(const char *path) __attribute__((weak));

/* xemu's qemu_init() builds its machine command line from g_config, which the
 * stock xemu main() loads first; the fuzz entry point does not. Load a
 * headless config here: the NULL nv2a renderer (no GL context needed), a
 * per-process data dir (eeprom, settings) in scratch space, and a flash file
 * plus show_welcome=false so the VM autostarts (a paused VM has no virtual
 * clock deadline, which makes the harness's clock_step op fail). */
/* The generic fuzzer is configured by QEMU_FUZZ_OBJECTS/QEMU_FUZZ_ARGS, which
 * a bare run (fuzz-smoke, Mayhem's cmd) does not set. Derive the objects
 * pattern from the directory holding the per-target binary
 * (.../<pattern>/qemu-fuzz-i386-target-generic-fuzz); explicit env wins. */
static void default_fuzz_env(void)
{
    char *name = program_invocation_name, *slash, *prev;
    size_t n;
    char pattern[128];

    setenv("QEMU_FUZZ_ARGS",
           "-machine xbox -nodefaults -audio driver=none -netdev user,id=n0", 0);
    slash = strrchr(name, '/');
    if (!slash) {
        return;
    }
    for (prev = slash; prev > name && prev[-1] != '/'; prev--) {
    }
    n = slash - prev;
    if (n > 0 && n < sizeof(pattern)) {
        memcpy(pattern, prev, n);
        pattern[n] = 0;
        setenv("QEMU_FUZZ_OBJECTS", pattern, 0);
    }
}

__attribute__((constructor)) static void xemu_fuzz_settings_init(void)
{
    const char *tmp = getenv("TMPDIR");
    char *dir, *cfg, *bios;
    FILE *f;

    if (!xemu_settings_load || !xemu_settings_set_path) {
        return;
    }
    default_fuzz_env();
    if (!tmp || !*tmp) {
        tmp = "/tmp";
    }
    dir = malloc(strlen(tmp) + sizeof("/xemu-fuzz.XXXXXX"));
    strcpy(dir, tmp);
    strcat(dir, "/xemu-fuzz.XXXXXX");
    if (!mkdtemp(dir)) {
        free(dir);
        return;
    }
    setenv("XDG_DATA_HOME", dir, 1);
    cfg = malloc(strlen(dir) + sizeof("/xemu.toml"));
    strcpy(cfg, dir);
    strcat(cfg, "/xemu.toml");
    bios = malloc(strlen(dir) + sizeof("/bios.bin"));
    strcpy(bios, dir);
    strcat(bios, "/bios.bin");
    f = fopen(bios, "w"); /* empty: xbox_flash_init() falls back to 0xff fill */
    if (f) {
        fclose(f);
    }
    f = fopen(cfg, "w");
    if (f) {
        fprintf(f, "[general]\nshow_welcome = false\n"
                   "[display]\nrenderer = 'NULL'\n"
                   "[sys.files]\nflashrom_path = '%s'\n", bios);
        fclose(f);
    }
    free(bios);
    xemu_settings_set_path(cfg); /* settings keep this pointer: never freed */
    free(dir);
    xemu_settings_load();
}
