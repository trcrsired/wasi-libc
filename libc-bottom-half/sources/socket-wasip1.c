// SPDX-License-Identifier: BSD-2-Clause
//
// WASI preview1 has no syscalls for creating or managing sockets; stock
// wasi-libc only provides accept/recv/send/shutdown on pre-opened socket
// descriptors. This file implements the rest of the POSIX socket API on top
// of the WAVM runtime's wasip1 socket extension imports (sock_open,
// sock_bind, sock_listen, sock_connect, sock_getlocaladdr, sock_getpeeraddr,
// sock_send_to, sock_recv_from, sock_setsockopt, sock_getsockopt), which are
// available when the runtime grants the process network access. A module
// that calls these functions can only run on a runtime providing the
// extension imports.
//
// The argument values (address families, socket types, SOL_*/SO_*/TCP_*/
// IPV6_* constants) intentionally match this libc's <sys/socket.h> and
// <netinet/*.h> values, so they can be passed through unmodified. Socket
// addresses use the POSIX struct sockaddr_in/sockaddr_in6 memory layout.

#include <sys/socket.h>

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <wasi/api.h>

#ifdef __wasm64__
#define WASI_EXT_NAME(name) name "_wasm64"
#else
#define WASI_EXT_NAME(name) name
#endif

#define WASI_EXT_IMPORT(name)                                                   \
	__attribute__((__import_module__("wasi_snapshot_preview1"),                 \
				   __import_name__(WASI_EXT_NAME(name))))

WASI_EXT_IMPORT("sock_open")
extern __wasi_errno_t __wasiext_sock_open(uint32_t address_family,
										  uint32_t socket_type,
										  __wasi_fd_t *out_fd);
WASI_EXT_IMPORT("sock_bind")
extern __wasi_errno_t __wasiext_sock_bind(__wasi_fd_t fd,
										  const void *address,
										  size_t address_len);
WASI_EXT_IMPORT("sock_listen")
extern __wasi_errno_t __wasiext_sock_listen(__wasi_fd_t fd, uint32_t backlog);
WASI_EXT_IMPORT("sock_connect")
extern __wasi_errno_t __wasiext_sock_connect(__wasi_fd_t fd,
											 const void *address,
											 size_t address_len);
WASI_EXT_IMPORT("sock_getlocaladdr")
extern __wasi_errno_t __wasiext_sock_getlocaladdr(__wasi_fd_t fd,
												  void *out_address,
												  size_t *inout_address_len);
WASI_EXT_IMPORT("sock_getpeeraddr")
extern __wasi_errno_t __wasiext_sock_getpeeraddr(__wasi_fd_t fd,
												 void *out_address,
												 size_t *inout_address_len);
WASI_EXT_IMPORT("sock_send_to")
extern __wasi_errno_t __wasiext_sock_send_to(__wasi_fd_t fd,
											 const __wasi_ciovec_t *si_data,
											 size_t si_data_len,
											 __wasi_siflags_t si_flags,
											 const void *dest_address,
											 size_t dest_address_len,
											 size_t *out_data_len);
WASI_EXT_IMPORT("sock_recv_from")
extern __wasi_errno_t __wasiext_sock_recv_from(__wasi_fd_t fd,
											   __wasi_iovec_t *ri_data,
											   size_t ri_data_len,
											   __wasi_riflags_t ri_flags,
											   void *out_source_address,
											   size_t *inout_source_address_len,
											   size_t *out_data_len,
											   __wasi_roflags_t *out_flags);
WASI_EXT_IMPORT("sock_setsockopt")
extern __wasi_errno_t __wasiext_sock_setsockopt(__wasi_fd_t fd,
												uint32_t level,
												uint32_t option_name,
												const void *option_value,
												size_t option_len);
WASI_EXT_IMPORT("sock_getsockopt")
extern __wasi_errno_t __wasiext_sock_getsockopt(__wasi_fd_t fd,
												uint32_t level,
												uint32_t option_name,
												void *out_option_value,
												size_t *inout_option_len);

int socket(int domain, int type, int protocol) {
	(void)protocol;

	// Strip the flag bits musl allows to be OR'd into the type. SOCK_CLOEXEC is
	// a no-op (WASI has no exec); SOCK_NONBLOCK is applied after creation.
	int nonblocking = type & SOCK_NONBLOCK;
	type &= ~(SOCK_NONBLOCK | SOCK_CLOEXEC);

	__wasi_fd_t fd;
	__wasi_errno_t error = __wasiext_sock_open(domain, type, &fd);
	if (error != 0) {
		errno = error;
		return -1;
	}

	if (nonblocking) {
		// Best-effort; keep the fd if the flag can't be applied.
		(void)!__wasi_fd_fdstat_set_flags(fd, __WASI_FDFLAGS_NONBLOCK);
	}
	return fd;
}

int connect(int socket, const struct sockaddr *address, socklen_t address_len) {
	__wasi_errno_t error = __wasiext_sock_connect(socket, address, address_len);
	if (error != 0) {
		errno = error;
		return -1;
	}
	return 0;
}

int bind(int socket, const struct sockaddr *address, socklen_t address_len) {
	__wasi_errno_t error = __wasiext_sock_bind(socket, address, address_len);
	if (error != 0) {
		errno = error;
		return -1;
	}
	return 0;
}

int listen(int socket, int backlog) {
	if (backlog < 0) { backlog = 0; }
	__wasi_errno_t error = __wasiext_sock_listen(socket, (uint32_t)backlog);
	if (error != 0) {
		errno = error;
		return -1;
	}
	return 0;
}

int getsockname(int socket, struct sockaddr *restrict address,
				socklen_t *restrict address_len) {
	size_t len = *address_len;
	__wasi_errno_t error = __wasiext_sock_getlocaladdr(socket, address, &len);
	if (error != 0) {
		errno = error;
		return -1;
	}
	*address_len = (socklen_t)len;
	return 0;
}

int getpeername(int socket, struct sockaddr *restrict address,
				socklen_t *restrict address_len) {
	size_t len = *address_len;
	__wasi_errno_t error = __wasiext_sock_getpeeraddr(socket, address, &len);
	if (error != 0) {
		errno = error;
		return -1;
	}
	*address_len = (socklen_t)len;
	return 0;
}

ssize_t sendto(int socket, const void *buffer, size_t length, int flags,
			   const struct sockaddr *dest_addr, socklen_t dest_len) {
	// The host socket layer always sends with MSG_NOSIGNAL semantics; any other
	// flags are unsupported.
	if (flags & ~MSG_NOSIGNAL) {
		errno = EOPNOTSUPP;
		return -1;
	}

	__wasi_ciovec_t iov = {.buf = buffer, .buf_len = length};
	size_t data_len;
	__wasi_errno_t error = __wasiext_sock_send_to(
		socket, &iov, 1, 0, dest_addr, dest_addr ? (size_t)dest_len : 0,
		&data_len);
	if (error != 0) {
		errno = error;
		return -1;
	}
	return data_len;
}

ssize_t recvfrom(int socket, void *restrict buffer, size_t length, int flags,
				 struct sockaddr *restrict address,
				 socklen_t *restrict address_len) {
	if (flags & ~(MSG_PEEK | MSG_WAITALL)) {
		errno = EOPNOTSUPP;
		return -1;
	}
	if (address != NULL && address_len == NULL) {
		errno = EINVAL;
		return -1;
	}

	__wasi_iovec_t iov = {.buf = buffer, .buf_len = length};
	size_t source_len = address != NULL ? (size_t)*address_len : 0;
	size_t data_len;
	__wasi_roflags_t out_flags;
	__wasi_errno_t error = __wasiext_sock_recv_from(
		socket, &iov, 1, (__wasi_riflags_t)flags, address,
		address != NULL ? &source_len : NULL, &data_len, &out_flags);
	if (error != 0) {
		errno = error;
		return -1;
	}
	if (address != NULL) { *address_len = (socklen_t)source_len; }
	return data_len;
}

int setsockopt(int socket, int level, int option_name,
			   const void *option_value, socklen_t option_len) {
	// The extension only supports 32-bit integer option values.
	if (option_len < 4) {
		errno = EINVAL;
		return -1;
	}
	__wasi_errno_t error = __wasiext_sock_setsockopt(
		socket, level, option_name, option_value, option_len);
	if (error != 0) {
		errno = error;
		return -1;
	}
	return 0;
}

int getsockopt(int socket, int level, int option_name,
			   void *restrict option_value, socklen_t *restrict option_len) {
	// The extension only supports 32-bit integer option values. Marshal through
	// a local so that callers passing a smaller buffer get POSIX truncation.
	int value = 0;
	size_t value_len = sizeof(value);
	__wasi_errno_t error = __wasiext_sock_getsockopt(socket, level, option_name,
													 &value, &value_len);
	if (error != 0) {
		errno = error;
		return -1;
	}
	memcpy(option_value, &value,
		   *option_len < sizeof(value) ? (size_t)*option_len : sizeof(value));
	*option_len = (socklen_t)value_len;
	return 0;
}
