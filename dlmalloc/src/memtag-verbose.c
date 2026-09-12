// Verbose diagnostics for dlmalloc's WebAssembly memory-tagging checks.
//
// fprintf can allocate memory, which is unsafe while the allocator is
// already handling an error, so this file implements an allocation-free
// replacement: fixed message pieces and formatted addresses are emitted
// directly with writev(2) to file descriptor 2, with no large buffer.
//
// __dlmalloc_memtag_verbose_abort is weak so embedders can override
// it by defining a strong symbol with the same name and signature.
//
// whichfunc identifies which diagnostic to report:
//   0 - dlfree:                  color mismatch on release
//   1 - dlrealloc:               color mismatch on reallocate
//   2 - dlrealloc_in_place:      color mismatch on reallocate
//   3 - dlmemalign:              alignment is not a power of 2
//   4 - dlmalloc_usable_size:    color mismatch on size query
//   5 - mspace_realloc:          color mismatch on reallocate
//   6 - mspace_realloc_in_place: color mismatch on reallocate

typedef __SIZE_TYPE__ size_t;
typedef __UINTPTR_TYPE__ uintptr_t;
typedef __PTRDIFF_TYPE__ ssize_t;

#ifndef __wasilibc_dlmalloc_memtag_noverbose

struct memtag_iovec {
    void *iov_base;
    size_t iov_len;
};

extern ssize_t pesudo_writev(int fd, struct memtag_iovec const *iov,
                             int iovcnt) __asm__("writev");

// Pair a string literal with its compile-time length.
#define MEMTAG_LIT(s) s, sizeof(s) - 1

// Writes the address as 0xFFFFFFFF on wasm32, 0xFFFFFFFFFFFFFFFF on wasm64.
// Returns the number of bytes written.
static size_t memtag_ptr(char *dst, void const *ptr) {
    uintptr_t v = (uintptr_t)ptr;
    size_t digits = sizeof(void *) * 2;
    __builtin_memcpy(dst, "0x", 2);
    for (size_t i = digits; i--;) {
        dst[2 + i] = "0123456789abcdef"[v & 0xf];
        v >>= 4;
    }
    return 2 + digits;
}

// Emits: head actual mid expected tail
static void memtag_emit(void *actual, void *expected,
                        char const *head, size_t head_len,
                        char const *mid, size_t mid_len,
                        char const *tail, size_t tail_len) {
    char abuf[2 + sizeof(void *) * 2];
    char ebuf[2 + sizeof(void *) * 2];
    struct memtag_iovec iov[] = {
        { (void *)head, head_len },
        { abuf, memtag_ptr(abuf, actual) },
        { (void *)mid, mid_len },
        { ebuf, memtag_ptr(ebuf, expected) },
        { (void *)tail, tail_len },
    };
    pesudo_writev(2, iov, (int)(sizeof(iov) / sizeof(iov[0])));
}

#endif /* !__wasilibc_dlmalloc_memtag_noverbose */

// When built with __wasilibc_dlmalloc_memtag_noverbose this is just a trap;
// since it is weak, embedders can still link in a diagnostic implementation
// to override it.
[[noreturn]] __attribute__((weak))
void __dlmalloc_memtag_verbose_abort(unsigned whichfunc, void *actual,
                                           void *expected) {
#ifndef __wasilibc_dlmalloc_memtag_noverbose
    switch (whichfunc) {
    case 0:
        memtag_emit(actual, expected,
            MEMTAG_LIT("dlfree detects a color mismatch in WebAssembly memory tagging: you attempt to release "),
            MEMTAG_LIT(", expected: "),
            MEMTAG_LIT(".\nThis is an incorrect deallocation, such as a double-free.\n"));
        break;
    case 1:
        memtag_emit(actual, expected,
            MEMTAG_LIT("dlrealloc detects a color mismatch in WebAssembly memory tagging: you attempt to reallocate at "),
            MEMTAG_LIT(", expected: "),
            MEMTAG_LIT(".\nThis is an incorrect reallocation.\n"));
        break;
    case 2:
        memtag_emit(actual, expected,
            MEMTAG_LIT("dlrealloc_in_place detects a color mismatch in WebAssembly memory tagging: you attempt to reallocate at "),
            MEMTAG_LIT(", expected: "),
            MEMTAG_LIT(".\nThis is an incorrect reallocation.\n"));
        break;
    case 3:
        memtag_emit(actual, expected,
            MEMTAG_LIT("dlmemalign detects an incorrect alignment in WebAssembly memory tagging. alignment must be power of 2. dlmemalign("),
            MEMTAG_LIT(", "),
            MEMTAG_LIT(")\n"));
        break;
    case 4:
        memtag_emit(actual, expected,
            MEMTAG_LIT("void dlmalloc_usable_size(void* mem) detects a color mismatch in WebAssembly memory tagging: you attempt to know the size of "),
            MEMTAG_LIT(", expected: "),
            MEMTAG_LIT(".\n"));
        break;
    case 5:
        memtag_emit(actual, expected,
            MEMTAG_LIT("mspace_realloc detects a color mismatch in WebAssembly memory tagging: you attempt to reallocate at "),
            MEMTAG_LIT(", expected: "),
            MEMTAG_LIT(".\nThis is an incorrect reallocation.\n"));
        break;
    case 6:
        memtag_emit(actual, expected,
            MEMTAG_LIT("mspace_realloc_in_place detects a color mismatch in WebAssembly memory tagging: you attempt to reallocate at "),
            MEMTAG_LIT(", expected: "),
            MEMTAG_LIT(".\nThis is an incorrect reallocation.\n"));
        break;
    default:
        break;
    }
#else
    (void)whichfunc;
    (void)actual;
    (void)expected;
#endif
    __builtin_trap();
}
