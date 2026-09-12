# Disable some warnings in this third-party code.
add_compile_options(-Wno-null-pointer-arithmetic -Wno-unused-but-set-variable)

add_object_library(dlmalloc src/dlmalloc.c src/memtag-verbose.c)
foreach(obj dlmalloc-shared dlmalloc-static)
  target_include_directories(${obj} PRIVATE include)
endforeach()

# Apply memory tagging flags only to dlmalloc (not other wasi-libc code)
# This matches the old Makefile behavior where $(DLMALLOC_OBJS) only got $(MEMTAGCFLAGS)
if(ENABLE_MEMTAG)
  target_compile_definitions(dlmalloc-shared PRIVATE __wasilibc_dlmalloc_enable_memtag)
  target_compile_definitions(dlmalloc-static PRIVATE __wasilibc_dlmalloc_enable_memtag)
  if(MEMTAG_NOVERBOSE)
    target_compile_definitions(dlmalloc-shared PRIVATE __wasilibc_dlmalloc_memtag_noverbose)
    target_compile_definitions(dlmalloc-static PRIVATE __wasilibc_dlmalloc_memtag_noverbose)
  endif()
endif()
