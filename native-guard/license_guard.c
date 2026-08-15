#define _GNU_SOURCE
#include <arpa/inet.h>
#include <android/log.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <jni.h>
#include <inttypes.h>
#include <link.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

enum {
  GUARD_TRACED = 1,
  GUARD_INJECTED_MAP = 2,
  GUARD_SUSPICIOUS_THREAD = 4,
  GUARD_INSTRUMENTATION_PORT = 8,
  GUARD_PRELOAD = 16,
  GUARD_HOOKED_LIBC = 32,
  GUARD_DUMPABLE = 64,
  GUARD_ANON_RWX = 128,
  GUARD_SUSPICIOUS_FD = 256,
  GUARD_INLINE_HOOK = 512,
  GUARD_IMPORT_TABLE = 1024,
  GUARD_TEXT_IMAGE = 2048
};

static _Atomic int guard_state;
static pthread_once_t watchdog_once = PTHREAD_ONCE_INIT;

static void report_state(const char *source, int state) {
  if (state == 0) return;
  __android_log_print(
      ANDROID_LOG_ERROR,
      "LicenseGuard",
      "%s state=0x%x tracer=%d maps=%d threads=%d port=%d preload=%d libc=%d dumpable=%d rwx=%d fd=%d inline=%d imports=%d text=%d",
      source,
      state,
      (state & GUARD_TRACED) != 0,
      (state & GUARD_INJECTED_MAP) != 0,
      (state & GUARD_SUSPICIOUS_THREAD) != 0,
      (state & GUARD_INSTRUMENTATION_PORT) != 0,
      (state & GUARD_PRELOAD) != 0,
      (state & GUARD_HOOKED_LIBC) != 0,
      (state & GUARD_DUMPABLE) != 0,
      (state & GUARD_ANON_RWX) != 0,
      (state & GUARD_SUSPICIOUS_FD) != 0,
      (state & GUARD_INLINE_HOOK) != 0,
      (state & GUARD_IMPORT_TABLE) != 0,
      (state & GUARD_TEXT_IMAGE) != 0);
}

static int ascii_contains_folded(const char *text, const char *needle) {
  if (text == NULL || needle == NULL || *needle == '\0') return 0;
  size_t n = strlen(needle);
  for (const char *p = text; *p != '\0'; ++p) {
    size_t i = 0;
    while (i < n && p[i] != '\0') {
      char a = p[i];
      char b = needle[i];
      if (a >= 'A' && a <= 'Z') a = (char)(a + ('a' - 'A'));
      if (b >= 'A' && b <= 'Z') b = (char)(b + ('a' - 'A'));
      if (a != b) break;
      ++i;
    }
    if (i == n) return 1;
  }
  return 0;
}

static void decode_pattern(char *out, const uint8_t *encoded, size_t size) {
  for (size_t i = 0; i < size; ++i) out[i] = (char)(encoded[i] ^ 0x5aU);
  out[size] = '\0';
}

static int contains_instrumentation_marker(const char *line) {
  static const uint8_t patterns[][16] = {
    {0x3c,0x28,0x33,0x3e,0x3b},
    {0x3d,0x2f,0x37,0x77,0x30,0x29,0x77,0x36,0x35,0x35,0x2a},
    {0x29,0x2f,0x38,0x29,0x2e,0x28,0x3b,0x2e,0x3f}
  };
  static const uint8_t lengths[] = {5,11,9};
  char pattern[17];
  for (size_t i = 0; i < sizeof(lengths); ++i) {
    decode_pattern(pattern, patterns[i], lengths[i]);
    if (ascii_contains_folded(line, pattern)) return 1;
  }
  return 0;
}

static int check_tracer(void) {
  FILE *file = fopen("/proc/self/status", "re");
  if (file == NULL) return 0;
  char line[256];
  int traced = 0;
  while (fgets(line, sizeof(line), file) != NULL) {
    if (strncmp(line, "TracerPid:", 10) == 0) {
      traced = strtol(line + 10, NULL, 10) != 0;
      break;
    }
  }
  fclose(file);
  return traced;
}

static int check_maps(void) {
  FILE *file = fopen("/proc/self/maps", "re");
  if (file == NULL) return 0;
  char line[1024];
  int found = 0;
  while (fgets(line, sizeof(line), file) != NULL) {
    if (contains_instrumentation_marker(line)) {
      found = 1;
      break;
    }
  }
  fclose(file);
  return found;
}

static int check_anonymous_rwx(void) {
  FILE *file = fopen("/proc/self/maps", "re");
  if (file == NULL) return 0;
  char line[1024];
  int found = 0;
  while (fgets(line, sizeof(line), file) != NULL) {
    char *permissions = strchr(line, ' ');
    if (permissions != NULL && strncmp(permissions + 1, "rwx", 3) == 0 &&
        (strstr(line, "[anon:") != NULL || strstr(line, "/memfd:") != NULL ||
         strchr(line, '/') == NULL)) {
      found = 1;
      break;
    }
  }
  fclose(file);
  return found;
}

static int check_suspicious_fds(void) {
  DIR *directory = opendir("/proc/self/fd");
  if (directory == NULL) return 0;
  struct dirent *entry;
  int found = 0;
  while ((entry = readdir(directory)) != NULL) {
    if (entry->d_name[0] == '.') continue;
    char path[128];
    char target[512];
    snprintf(path, sizeof(path), "/proc/self/fd/%s", entry->d_name);
    ssize_t size = readlink(path, target, sizeof(target) - 1);
    if (size <= 0) continue;
    target[size] = '\0';
    if (contains_instrumentation_marker(target)) {
      found = 1;
      break;
    }
  }
  closedir(directory);
  return found;
}

static int check_unix_sockets(void) {
  FILE *file = fopen("/proc/net/unix", "re");
  if (file == NULL) return 0;
  char line[1024];
  int found = 0;
  while (fgets(line, sizeof(line), file) != NULL) {
    if (contains_instrumentation_marker(line)) {
      found = 1;
      break;
    }
  }
  fclose(file);
  return found;
}

static int check_threads(void) {
  DIR *directory = opendir("/proc/self/task");
  if (directory == NULL) return 0;
  struct dirent *entry;
  int found = 0;
  while ((entry = readdir(directory)) != NULL) {
    if (entry->d_name[0] == '.') continue;
    char path[128];
    snprintf(path, sizeof(path), "/proc/self/task/%s/comm", entry->d_name);
    FILE *file = fopen(path, "re");
    if (file == NULL) continue;
    char name[128] = {0};
    if (fgets(name, sizeof(name), file) != NULL && contains_instrumentation_marker(name)) found = 1;
    fclose(file);
    if (found) break;
  }
  closedir(directory);
  return found;
}

static int port_open(uint16_t port) {
  int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return 0;
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
  struct sockaddr_in address;
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_port = htons(port);
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  int result = connect(fd, (struct sockaddr *)&address, sizeof(address));
  int open = result == 0 || errno == EINPROGRESS;
  if (open && result != 0) {
    fd_set write_set;
    FD_ZERO(&write_set);
    FD_SET(fd, &write_set);
    struct timeval timeout = {.tv_sec = 0, .tv_usec = 30000};
    if (select(fd + 1, NULL, &write_set, NULL, &timeout) > 0) {
      int error = 0;
      socklen_t length = sizeof(error);
      open = getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && error == 0;
    } else {
      open = 0;
    }
  }
  close(fd);
  return open;
}

static int check_preload(void) {
  const char *preload = getenv("LD_PRELOAD");
  return preload != NULL && *preload != '\0';
}

static int check_libc_origin(void) {
  Dl_info info;
  memset(&info, 0, sizeof(info));
  void *symbol = dlsym(RTLD_DEFAULT, "open");
  if (symbol == NULL || dladdr(symbol, &info) == 0 || info.dli_fname == NULL) return 0;
  return strstr(info.dli_fname, "libc.so") == NULL;
}

static int symbol_bytes_differ(const char *name) {
  const uint8_t *symbol = (const uint8_t *)dlsym(RTLD_DEFAULT, name);
  if (symbol == NULL) return 0;
  FILE *maps = fopen("/proc/self/maps", "re");
  if (maps == NULL) return 0;
  char line[1024];
  uintptr_t start = 0;
  uintptr_t end = 0;
  unsigned long long file_offset = 0;
  char permissions[5] = {0};
  char mapped_path[768] = {0};
  while (fgets(line, sizeof(line), maps) != NULL) {
    uintptr_t candidate_start = 0;
    uintptr_t candidate_end = 0;
    unsigned long long candidate_offset = 0;
    char candidate_permissions[5] = {0};
    char candidate_path[768] = {0};
    int fields = sscanf(
        line,
        "%" SCNxPTR "-%" SCNxPTR " %4s %llx %*s %*s %767[^\n]",
        &candidate_start,
        &candidate_end,
        candidate_permissions,
        &candidate_offset,
        candidate_path);
    uintptr_t address = (uintptr_t)symbol;
    if (fields >= 4 && address >= candidate_start && address + 16U <= candidate_end) {
      start = candidate_start;
      end = candidate_end;
      file_offset = candidate_offset;
      memcpy(permissions, candidate_permissions, sizeof(permissions));
      if (fields == 5) {
        const char *path_start = candidate_path;
        while (*path_start == ' ') ++path_start;
        snprintf(mapped_path, sizeof(mapped_path), "%s", path_start);
      }
      break;
    }
  }
  fclose(maps);
  if (start == 0 || end <= start || permissions[0] != 'r' || permissions[2] != 'x' || mapped_path[0] != '/') return 0;
  char *deleted = strstr(mapped_path, " (deleted)");
  if (deleted != NULL) *deleted = '\0';
  int fd = open(mapped_path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return 0;
  uint8_t disk[16];
  off_t offset = (off_t)(file_offset + ((uintptr_t)symbol - start));
  ssize_t size = pread(fd, disk, sizeof(disk), offset);
  close(fd);
  if (size != (ssize_t)sizeof(disk)) return 0;
  return memcmp(symbol, disk, sizeof(disk)) != 0;
}

static int check_inline_hooks(void) {
  static const char *symbols[] = {"open", "read", "dlopen", "pthread_create"};
  for (size_t i = 0; i < sizeof(symbols) / sizeof(symbols[0]); ++i) {
    if (symbol_bytes_differ(symbols[i])) return 1;
  }
  return 0;
}

typedef struct {
  uintptr_t base;
  const ElfW(Phdr) *headers;
  ElfW(Half) count;
} module_image;

typedef struct {
  uintptr_t address;
  module_image image;
  int found;
} module_lookup;

#if defined(__LP64__)
#define AVMP_R_TYPE(value) ELF64_R_TYPE(value)
#else
#define AVMP_R_TYPE(value) ELF32_R_TYPE(value)
#endif

static int address_in_load_segment(
    const module_image *image,
    uintptr_t address,
    size_t size,
    uint32_t required_flags) {
  if (image == NULL || size == 0 || address > UINTPTR_MAX - size) return 0;
  uintptr_t end = address + size;
  for (ElfW(Half) i = 0; i < image->count; ++i) {
    const ElfW(Phdr) *header = &image->headers[i];
    if (header->p_type != PT_LOAD || (header->p_flags & required_flags) != required_flags) continue;
    uintptr_t start = image->base + (uintptr_t)header->p_vaddr;
    if ((uintptr_t)header->p_memsz > UINTPTR_MAX - start) continue;
    uintptr_t limit = start + (uintptr_t)header->p_memsz;
    if (address >= start && end <= limit) return 1;
  }
  return 0;
}

static int module_lookup_callback(struct dl_phdr_info *info, size_t size, void *opaque) {
  (void)size;
  module_lookup *lookup = (module_lookup *)opaque;
  module_image image = {
      .base = (uintptr_t)info->dlpi_addr,
      .headers = info->dlpi_phdr,
      .count = info->dlpi_phnum};
  if (!address_in_load_segment(&image, lookup->address, 1, PF_X)) return 0;
  lookup->image = image;
  lookup->found = 1;
  return 1;
}

static int self_image(module_image *image) {
  module_lookup lookup = {.address = (uintptr_t)&self_image, .found = 0};
  dl_iterate_phdr(module_lookup_callback, &lookup);
  if (!lookup.found) return 0;
  *image = lookup.image;
  return 1;
}

static uintptr_t dynamic_pointer(const module_image *image, ElfW(Addr) value, size_t size) {
  uintptr_t direct = (uintptr_t)value;
  if (address_in_load_segment(image, direct, size, PF_R)) return direct;
  if ((uintptr_t)value <= UINTPTR_MAX - image->base) {
    uintptr_t relative = image->base + (uintptr_t)value;
    if (address_in_load_segment(image, relative, size, PF_R)) return relative;
  }
  return 0;
}

static int address_is_executable(uintptr_t address) {
  FILE *file = fopen("/proc/self/maps", "re");
  if (file == NULL) return 0;
  char line[1024];
  int executable = 0;
  while (fgets(line, sizeof(line), file) != NULL) {
    uintptr_t start = 0;
    uintptr_t end = 0;
    char permissions[5] = {0};
    if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %4s", &start, &end, permissions) == 3 &&
        address >= start && address < end) {
      executable = permissions[2] == 'x';
      break;
    }
  }
  fclose(file);
  return executable;
}

static int import_relocation_type(ElfW(Xword) type) {
#if defined(__aarch64__)
  return type == R_AARCH64_GLOB_DAT || type == R_AARCH64_JUMP_SLOT;
#elif defined(__arm__)
  return type == R_ARM_GLOB_DAT || type == R_ARM_JUMP_SLOT;
#elif defined(__x86_64__)
  return type == R_X86_64_GLOB_DAT || type == R_X86_64_JUMP_SLOT;
#elif defined(__i386__)
  return type == R_386_GLOB_DAT || type == R_386_JMP_SLOT;
#else
  (void)type;
  return 0;
#endif
}

static int validate_import_target(uintptr_t target) {
  if (target == 0) return 0;
  if (!address_is_executable(target)) return 1;
  Dl_info info;
  memset(&info, 0, sizeof(info));
  if (dladdr((const void *)target, &info) == 0 || info.dli_fname == NULL) return 1;
  return contains_instrumentation_marker(info.dli_fname);
}

static int scan_rela_table(const module_image *image, uintptr_t table, size_t bytes) {
  if (table == 0 || bytes == 0) return 0;
  if (bytes % sizeof(ElfW(Rela)) != 0 || !address_in_load_segment(image, table, bytes, PF_R)) return 1;
  const ElfW(Rela) *entries = (const ElfW(Rela) *)table;
  size_t count = bytes / sizeof(ElfW(Rela));
  for (size_t i = 0; i < count; ++i) {
    if (!import_relocation_type(AVMP_R_TYPE(entries[i].r_info))) continue;
    uintptr_t slot = image->base + (uintptr_t)entries[i].r_offset;
    if (!address_in_load_segment(image, slot, sizeof(uintptr_t), PF_W)) return 1;
    uintptr_t target = 0;
    memcpy(&target, (const void *)slot, sizeof(target));
    if (validate_import_target(target)) return 1;
  }
  return 0;
}

static int scan_rel_table(const module_image *image, uintptr_t table, size_t bytes) {
  if (table == 0 || bytes == 0) return 0;
  if (bytes % sizeof(ElfW(Rel)) != 0 || !address_in_load_segment(image, table, bytes, PF_R)) return 1;
  const ElfW(Rel) *entries = (const ElfW(Rel) *)table;
  size_t count = bytes / sizeof(ElfW(Rel));
  for (size_t i = 0; i < count; ++i) {
    if (!import_relocation_type(AVMP_R_TYPE(entries[i].r_info))) continue;
    uintptr_t slot = image->base + (uintptr_t)entries[i].r_offset;
    if (!address_in_load_segment(image, slot, sizeof(uintptr_t), PF_W)) return 1;
    uintptr_t target = 0;
    memcpy(&target, (const void *)slot, sizeof(target));
    if (validate_import_target(target)) return 1;
  }
  return 0;
}

static int check_import_table(void) {
  module_image image;
  if (!self_image(&image)) return 1;
  const ElfW(Dyn) *dynamic = NULL;
  size_t dynamic_count = 0;
  for (ElfW(Half) i = 0; i < image.count; ++i) {
    const ElfW(Phdr) *header = &image.headers[i];
    if (header->p_type == PT_DYNAMIC) {
      dynamic = (const ElfW(Dyn) *)(image.base + (uintptr_t)header->p_vaddr);
      dynamic_count = (size_t)header->p_memsz / sizeof(ElfW(Dyn));
      break;
    }
  }
  if (dynamic == NULL || dynamic_count == 0 || dynamic_count > 4096) return 1;
  uintptr_t jmprel = 0;
  size_t pltrelsz = 0;
  ElfW(Sxword) pltrel = 0;
  uintptr_t rela = 0;
  size_t relasz = 0;
  uintptr_t rel = 0;
  size_t relsz = 0;
  for (size_t i = 0; i < dynamic_count && dynamic[i].d_tag != DT_NULL; ++i) {
    switch (dynamic[i].d_tag) {
      case DT_JMPREL: jmprel = dynamic_pointer(&image, dynamic[i].d_un.d_ptr, sizeof(ElfW(Addr))); break;
      case DT_PLTRELSZ: pltrelsz = (size_t)dynamic[i].d_un.d_val; break;
      case DT_PLTREL: pltrel = dynamic[i].d_un.d_val; break;
      case DT_RELA: rela = dynamic_pointer(&image, dynamic[i].d_un.d_ptr, sizeof(ElfW(Rela))); break;
      case DT_RELASZ: relasz = (size_t)dynamic[i].d_un.d_val; break;
      case DT_REL: rel = dynamic_pointer(&image, dynamic[i].d_un.d_ptr, sizeof(ElfW(Rel))); break;
      case DT_RELSZ: relsz = (size_t)dynamic[i].d_un.d_val; break;
      default: break;
    }
  }
  if (pltrelsz != 0 && (jmprel == 0 || (pltrel != DT_RELA && pltrel != DT_REL))) return 1;
  if (pltrel == DT_RELA && scan_rela_table(&image, jmprel, pltrelsz)) return 1;
  if (pltrel == DT_REL && scan_rel_table(&image, jmprel, pltrelsz)) return 1;
  if (rela != jmprel && scan_rela_table(&image, rela, relasz)) return 1;
  if (rel != jmprel && scan_rel_table(&image, rel, relsz)) return 1;
  return 0;
}

static int check_text_image(void) {
  module_image image;
  if (!self_image(&image)) return 1;
  Dl_info info;
  memset(&info, 0, sizeof(info));
  if (dladdr((const void *)&check_text_image, &info) == 0 || info.dli_fname == NULL) return 1;
  if (info.dli_fname[0] != '/' || strchr(info.dli_fname, '!') != NULL) return 0;
  int fd = open(info.dli_fname, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return 0;
  uint8_t disk[4096];
  int mismatch = 0;
  for (ElfW(Half) i = 0; i < image.count && !mismatch; ++i) {
    const ElfW(Phdr) *header = &image.headers[i];
    if (header->p_type != PT_LOAD || (header->p_flags & PF_X) == 0) continue;
    uintptr_t memory = image.base + (uintptr_t)header->p_vaddr;
    size_t remaining = (size_t)header->p_filesz;
    off_t offset = (off_t)header->p_offset;
    while (remaining != 0) {
      size_t amount = remaining < sizeof(disk) ? remaining : sizeof(disk);
      ssize_t read_size = pread(fd, disk, amount, offset);
      if (read_size != (ssize_t)amount || memcmp((const void *)memory, disk, amount) != 0) {
        mismatch = 1;
        break;
      }
      memory += amount;
      offset += (off_t)amount;
      remaining -= amount;
    }
  }
  close(fd);
  return mismatch;
}

static int probe(void) {
  int state = 0;
  if (check_tracer()) state |= GUARD_TRACED;
  if (check_maps() || check_unix_sockets()) state |= GUARD_INJECTED_MAP;
  if (check_threads()) state |= GUARD_SUSPICIOUS_THREAD;
  if (port_open(27042) || port_open(27043)) state |= GUARD_INSTRUMENTATION_PORT;
  if (check_preload()) state |= GUARD_PRELOAD;
  if (check_libc_origin()) state |= GUARD_HOOKED_LIBC;
  if (prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0) state |= GUARD_DUMPABLE;
  if (check_anonymous_rwx()) state |= GUARD_ANON_RWX;
  if (check_suspicious_fds()) state |= GUARD_SUSPICIOUS_FD;
  if (check_inline_hooks()) state |= GUARD_INLINE_HOOK;
  if (check_import_table()) state |= GUARD_IMPORT_TABLE;
  if (check_text_image()) state |= GUARD_TEXT_IMAGE;
  return state;
}

static void *watchdog(void *unused) {
  (void)unused;
  prctl(PR_SET_NAME, "license-health", 0, 0, 0);
  for (;;) {
    int state = probe();
    atomic_store_explicit(&guard_state, state, memory_order_release);
    if (state != 0) report_state("watchdog", state);
    struct timespec delay = {.tv_sec = 1, .tv_nsec = 700000000L};
    nanosleep(&delay, NULL);
  }
  return NULL;
}

static void start_watchdog(void) {
  pthread_t thread;
  if (pthread_create(&thread, NULL, watchdog, NULL) == 0) pthread_detach(thread);
}

__attribute__((visibility("default")))
JNIEXPORT jint JNICALL
Java_com_android_licenseguard_NativeBridge_nativeProbe(JNIEnv *env, jclass type) {
  (void)env;
  (void)type;
  pthread_once(&watchdog_once, start_watchdog);
  int state = probe();
  atomic_store_explicit(&guard_state, state, memory_order_release);
  report_state("jni", state);
  return state;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
  (void)vm;
  (void)reserved;
  prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
  pthread_once(&watchdog_once, start_watchdog);
  return JNI_VERSION_1_6;
}
