#define _GNU_SOURCE
#include <errno.h>
#include <ftw.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <string.h>
#include <ucontext.h>
#include <unistd.h>

/* Weak: absent in a build without ASan. */
extern void __sanitizer_set_report_fd(void *fd) __attribute__((weak));
extern void __sanitizer_set_report_path(const char *path) __attribute__((weak));

/* Weak, so the object also links into configure's throwaway test programs. */
extern bool xemu_settings_load(void) __attribute__((weak));
extern void xemu_settings_set_path(const char *path) __attribute__((weak));

/* Weak QEMU entry points for the SMBus slave restore below; I2CBus/Object/DeviceState are only ever
 * passed through as opaque pointers (BusState is the first member of I2CBus). */
extern void register_module_init(void (*fn)(void), int type) __attribute__((weak));
extern void qemu_register_reset(void (*func)(void *), void *opaque) __attribute__((weak));
extern void *object_resolve_path_type(const char *path, const char *typename,
                                      bool *ambiguous) __attribute__((weak));
extern void *qdev_get_parent_bus(const void *dev) __attribute__((weak));
extern int i2c_bus_busy(void *bus) __attribute__((weak));
extern int i2c_start_send(void *bus, uint8_t address) __attribute__((weak));
extern int i2c_start_recv(void *bus, uint8_t address) __attribute__((weak));
extern int i2c_send(void *bus, uint8_t data) __attribute__((weak));
extern uint8_t i2c_recv(void *bus) __attribute__((weak));
extern void i2c_nack(void *bus) __attribute__((weak));
extern void i2c_end_transfer(void *bus) __attribute__((weak));
extern void *object_resolve_path_component(void *parent, const char *part) __attribute__((weak));
extern void qemu_set_irq(void *irq, int level) __attribute__((weak));

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

/* ASan prints "==PID==WARNING: ASan doesn't fully support makecontext/swapcontext" once per
 * process, on the first swapcontext (QEMU's coroutine creation). Mayhem's per-input replays
 * treat any "==PID==" line as a sanitizer report, so every input looked like a backtrace-less
 * crash titled by that warning. Trigger the one-shot warning here with sanitizer output sent
 * to a throwaway memfd, then point it back at stderr: real reports are untouched. */
static void consume_swapcontext_warning(void)
{
    const char *opts = getenv("ASAN_OPTIONS");
    ucontext_t uc;
    int fd;

    if (!__sanitizer_set_report_fd || !__sanitizer_set_report_path ||
        (opts && strstr(opts, "log_path"))) {
        return;
    }
    fd = memfd_create("sanitizer-warning", 0);
    if (fd < 0) {
        return;
    }
    __sanitizer_set_report_fd((void *)(long)fd);
    if (getcontext(&uc) == 0) {
        swapcontext(&uc, &uc);
    }
    __sanitizer_set_report_path("stderr"); /* also closes fd */
}

/* The fuzz entry point resets between inputs with qemu_system_reset() only, and none of the Xbox
 * SMBus slaves has a reset handler, so whatever an input writes through the SMBus host would stay
 * in them for every later input. A reset handler therefore puts every slave on the bus back to the
 * state it has after realize, through the slaves' own SMBus interface (hw/xbox/smbus_*.c):
 *   0x54 smbus-storage   256-byte EEPROM image, rewritten from a fixed pattern (also fixed so that
 *                        xemu does not generate a random serial/keys per process); the file too
 *   0x45/0x6A/0x70       cx25871 / fs454 / xcalibur video encoder: registers[256] zeroed, cmd = 0
 *   0x4C adm1032         cmd = 0
 *   0x10 smbus-xbox-smc  version index, error and scratch registers rewritten, intstatus (cleared
 *                        on read) read once, cmd = 0; scratch's boot value is read at the first reset
 * The SMBus host controller (xbox-smbus, hw/xbox/amd_smbus.c) has no reset handler either: its
 * registers and 32-byte block buffer are zeroed and its IRQ line lowered, as after realize.
 * A START+STOP with no data first returns each slave's protocol state machine (mode, data_len) to
 * idle. Only the slaves of the running machine answer; the other addresses are skipped. */
#define EEPROM_SIZE 256
#define EEPROM_ADDR 0x54
#define SMBUS_CHUNK 32 /* command byte + chunk fits SMBus's write buffer */
#define MODULE_INIT_LIBQOS 6 /* include/qemu/module.h: after MODULE_INIT_QOM, so QOM types exist */

static const uint8_t slave_addrs[] = { 0x10, 0x45, 0x4C, 0x54, 0x6A, 0x70 };
static const uint8_t encoder_addrs[] = { 0x45, 0x6A, 0x70 };
#define SMC_ADDR 0x10
#define ADM1032_ADDR 0x4C
#define SMC_REG_VER 0x01
#define SMC_REG_ERROR_WRITE 0x0e
#define SMC_REG_INTSTATUS 0x11
#define SMC_REG_SCRATCH 0x1b

/* Mirror of AMD756SMBus (hw/xbox/amd_smbus.h), which sits right before the smb_bar MemoryRegion in
 * XBOX_SMBState (hw/xbox/xbox_pci.h); only used after checking that .smbus is the bus the slaves
 * hang off. */
struct amd756_smbus_mirror {
    void *smbus;
    uint8_t regs[6 + 32 + 1]; /* stat ctl cmd addr data0 data1 data[32] index */
    void *irq;
};

static uint8_t pristine_eeprom[EEPROM_SIZE];
static uint8_t smc_scratch_boot;
static bool smc_scratch_known;

/* One SMBus write transfer: command byte, then len data bytes. False if no slave answers. */
static bool smbus_write(void *bus, uint8_t addr, uint8_t cmd, const uint8_t *data, int len)
{
    int i;

    if (i2c_start_send(bus, addr)) {
        return false;
    }
    i2c_send(bus, cmd);
    for (i = 0; i < len; i++) {
        i2c_send(bus, data[i]);
    }
    i2c_end_transfer(bus);
    return true;
}

/* Write-then-read with a repeated start, as the guest's read-byte-data does. */
static uint8_t smbus_read_reg(void *bus, uint8_t addr, uint8_t reg)
{
    uint8_t v;

    if (i2c_start_send(bus, addr)) {
        return 0;
    }
    i2c_send(bus, reg);
    if (i2c_start_recv(bus, addr)) {
        i2c_end_transfer(bus);
        return 0;
    }
    v = i2c_recv(bus);
    i2c_nack(bus);
    i2c_end_transfer(bus);
    return v;
}

static void restore_smbus_host(void *bus)
{
    void *host = object_resolve_path_type("", "xbox-smbus", NULL);
    void *bar = host ? object_resolve_path_component(host, "xbox-smbus-bar[0]") : NULL;
    struct amd756_smbus_mirror *smb = NULL;
    int off;

    if (!bar || !qemu_set_irq) {
        return;
    }
    /* smb ends before smb_bar, up to MemoryRegion's alignment of padding in between; its first
     * field, the I2C bus pointer, is the only copy of it in that window. */
    for (off = sizeof(*smb); off <= 2 * (int)sizeof(*smb); off += sizeof(void *)) {
        struct amd756_smbus_mirror *cand = (struct amd756_smbus_mirror *)((char *)bar - off);
        if (cand->smbus == bus) {
            smb = cand;
            break;
        }
    }
    if (!smb) {
        return;
    }
    if (smb->irq) {
        qemu_set_irq(smb->irq, 0);
    }
    memset(smb->regs, 0, sizeof(smb->regs));
}

static void restore_smbus_slaves(void *opaque)
{
    void *dev = object_resolve_path_type("", "smbus-storage", NULL);
    void *bus = dev ? qdev_get_parent_bus(dev) : NULL;
    static const uint8_t zeros[SMBUS_CHUNK];
    uint8_t zero = 0;
    int off, i;

    if (!bus) {
        return;
    }
    /* A transfer an input left open would receive our bytes; close it first. */
    if (i2c_bus_busy(bus)) {
        i2c_end_transfer(bus);
    }
    restore_smbus_host(bus);
    for (i = 0; i < sizeof(slave_addrs); i++) {
        if (!i2c_start_send(bus, slave_addrs[i])) {
            i2c_end_transfer(bus);
        }
    }

    for (off = 0; off < EEPROM_SIZE; off += SMBUS_CHUNK) {
        if (!smbus_write(bus, EEPROM_ADDR, off, pristine_eeprom + off, SMBUS_CHUNK)) {
            break;
        }
    }

    for (i = 0; i < sizeof(encoder_addrs); i++) {
        for (off = 0; off < 256; off += SMBUS_CHUNK) {
            if (!smbus_write(bus, encoder_addrs[i], off, zeros, SMBUS_CHUNK)) {
                break;
            }
        }
        smbus_write(bus, encoder_addrs[i], 0, NULL, 0);
    }

    smbus_write(bus, ADM1032_ADDR, 0, NULL, 0);

    if (!i2c_start_send(bus, SMC_ADDR)) {
        i2c_end_transfer(bus);
        if (!smc_scratch_known) {
            smc_scratch_boot = smbus_read_reg(bus, SMC_ADDR, SMC_REG_SCRATCH);
            smc_scratch_known = true;
        }
        smbus_write(bus, SMC_ADDR, SMC_REG_VER, &zero, 1);
        smbus_write(bus, SMC_ADDR, SMC_REG_ERROR_WRITE, &zero, 1);
        smbus_write(bus, SMC_ADDR, SMC_REG_SCRATCH, &smc_scratch_boot, 1);
        smbus_read_reg(bus, SMC_ADDR, SMC_REG_INTSTATUS);
        smbus_write(bus, SMC_ADDR, 0, NULL, 0);
    }
}

static void register_smbus_restore(void)
{
    qemu_register_reset(restore_smbus_slaves, NULL);
}

static char *scratch_dir;

static int remove_entry(const char *path, const struct stat *sb, int type,
                        struct FTW *ftw)
{
    return remove(path);
}

static void remove_scratch_dir(void)
{
    nftw(scratch_dir, remove_entry, 8, FTW_DEPTH | FTW_PHYS);
}

__attribute__((constructor)) static void xemu_fuzz_settings_init(void)
{
    const char *tmp = getenv("TMPDIR");
    char *dir, *cfg, *bios, *eeprom;
    FILE *f;
    int i;

    if (!xemu_settings_load || !xemu_settings_set_path) {
        return;
    }
    default_fuzz_env();
    consume_swapcontext_warning();
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
    scratch_dir = dir;
    atexit(remove_scratch_dir);
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
    eeprom = malloc(strlen(dir) + sizeof("/eeprom.bin"));
    strcpy(eeprom, dir);
    strcat(eeprom, "/eeprom.bin");
    for (i = 0; i < EEPROM_SIZE; i++) {
        pristine_eeprom[i] = (uint8_t)(i * 37 + 11);
    }
    f = fopen(eeprom, "w");
    if (f) {
        fwrite(pristine_eeprom, 1, EEPROM_SIZE, f);
        fclose(f);
    }
    f = fopen(cfg, "w");
    if (f) {
        fprintf(f, "[general]\nshow_welcome = false\n"
                   "[display]\nrenderer = 'NULL'\n"
                   "[sys.files]\nflashrom_path = '%s'\neeprom_path = '%s'\n",
                bios, eeprom);
        fclose(f);
    }
    free(bios);
    free(eeprom);
    if (register_module_init && qemu_register_reset && object_resolve_path_type &&
        qdev_get_parent_bus && object_resolve_path_component && qemu_set_irq &&
        i2c_bus_busy && i2c_start_send && i2c_start_recv &&
        i2c_send && i2c_recv && i2c_nack && i2c_end_transfer) {
        register_module_init(register_smbus_restore, MODULE_INIT_LIBQOS);
    }
    xemu_settings_set_path(cfg); /* settings keep this pointer: never freed */
    xemu_settings_load();
}
