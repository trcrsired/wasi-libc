typedef int16_t int_fast16_t;
typedef int32_t int_fast32_t;
typedef uint16_t uint_fast16_t;
typedef uint32_t uint_fast32_t;

#define INT_FAST16_MIN  INT16_MIN
#define INT_FAST32_MIN  INT32_MIN

#define INT_FAST16_MAX  INT16_MAX
#define INT_FAST32_MAX  INT32_MAX

#define UINT_FAST16_MAX UINT16_MAX
#define UINT_FAST32_MAX UINT32_MAX

#ifdef __wasm64__
#define INTPTR_MIN      INT64_MIN
#define INTPTR_MAX      INT64_MAX
#define UINTPTR_MAX     UINT64_MAX
#define PTRDIFF_MIN     INT64_MIN
#define PTRDIFF_MAX     INT64_MAX
#define SIZE_MAX        UINT64_MAX
#else
#define INTPTR_MIN      INT32_MIN
#define INTPTR_MAX      INT32_MAX
#define UINTPTR_MAX     UINT32_MAX
#define PTRDIFF_MIN     INT32_MIN
#define PTRDIFF_MAX     INT32_MAX
#define SIZE_MAX        UINT32_MAX
#endif
