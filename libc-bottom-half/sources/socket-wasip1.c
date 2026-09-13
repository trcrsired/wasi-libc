// SPDX-License-Identifier: BSD-2-Clause
//
// WASI preview1 has no syscalls for creating or managing sockets; stock
// wasi-libc only provides accept/recv/send/shutdown on pre-opened socket
// descriptors. This file implements the rest of the POSIX socket API on top
// of the WASIX socket extension imports (sock_open, sock_bind, sock_listen,
// sock_connect, sock_accept_v2, sock_addr_local, sock_addr_peer,
// sock_send_to, sock_recv_from, sock_send_file, sock_pair, sock_status,
// sock_set/get_opt_flag/time/size, resolve) exported by
// "wasi_snapshot_preview1" when the runtime grants the process network
// access. A module that calls these functions can only run on a runtime
// providing the extension imports.
//
// All wire formats are the WASIX ABI: addresses are exchanged as 110-byte
// __wasi_addr_port_t tagged unions ({u8 tag; u16 host-order port at offset 2;
// IP bytes in network order at offset 4}), resolve() returns 18-byte
// __wasi_addr_ip_t records, and socket options use the WASIX
// __wasi_sock_option_t tags with the flag/time/size syscall triple.

#include <sys/socket.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/time.h>
#include <wasi/api.h>

#ifdef __wasm64__
#define WASI_EXT_NAME(name) name "_wasm64"
#else
#define WASI_EXT_NAME(name) name
#endif

#define WASI_EXT_IMPORT(name)                                                   \
	__attribute__((__import_module__("wasi_snapshot_preview1"),                 \
				   __import_name__(WASI_EXT_NAME(name))))

// WASIX wire types (matching wasix-libc's <wasi/api_wasix.h>).

#define WASIX_AF_UNSPEC 0
#define WASIX_AF_INET4 1
#define WASIX_AF_INET6 2
#define WASIX_AF_UNIX 3

#define WASIX_SOCK_STREAM 1
#define WASIX_SOCK_DGRAM 2

#define WASIX_PROTO_IP 0
#define WASIX_PROTO_TCP 6
#define WASIX_PROTO_UDP 17

#define WASIX_SIFLAGS_SEND_DONT_WAIT 0x0001
#define WASIX_RIFLAGS_RECV_DONT_WAIT 0x0008

// __wasi_sock_option_t tags.
#define WASIX_OPT_REUSE_PORT 1
#define WASIX_OPT_REUSE_ADDR 2
#define WASIX_OPT_NO_DELAY 3
#define WASIX_OPT_DONT_ROUTE 4
#define WASIX_OPT_ONLY_V6 5
#define WASIX_OPT_BROADCAST 6
#define WASIX_OPT_MULTICAST_LOOP_V4 7
#define WASIX_OPT_MULTICAST_LOOP_V6 8
#define WASIX_OPT_LISTENING 10
#define WASIX_OPT_LAST_ERROR 11
#define WASIX_OPT_KEEP_ALIVE 12
#define WASIX_OPT_LINGER 13
#define WASIX_OPT_OOB_INLINE 14
#define WASIX_OPT_RECV_BUF_SIZE 15
#define WASIX_OPT_SEND_BUF_SIZE 16
#define WASIX_OPT_RECV_LOWAT 17
#define WASIX_OPT_SEND_LOWAT 18
#define WASIX_OPT_RECV_TIMEOUT 19
#define WASIX_OPT_SEND_TIMEOUT 20
#define WASIX_OPT_TTL 23
#define WASIX_OPT_MULTICAST_TTL_V4 24
#define WASIX_OPT_TYPE 25
#define WASIX_OPT_PROTO 26

#define WASIX_OPTION_SOME 1

typedef struct {
	uint16_t port; // host byte order
	uint8_t addr[4]; // network byte order
} wasix_addr_ip4_port_t;

typedef struct {
	uint16_t port; // host byte order
	uint16_t n[8]; // 16 address bytes in network order
	uint16_t flow_info1; // most significant two bytes of the 32-bit flow info
	uint16_t flow_info0; // least significant two bytes
	uint16_t scope_id1; // most significant two bytes of the 32-bit scope id
	uint16_t scope_id0; // least significant two bytes
} wasix_addr_ip6_port_t;

typedef struct {
	uint8_t tag;
	union {
		uint8_t unspec;
		wasix_addr_ip4_port_t inet4;
		wasix_addr_ip6_port_t inet6;
		uint8_t unix[108];
	} u;
} wasix_addr_port_t;

_Static_assert(sizeof(wasix_addr_port_t) == 110, "addr_port size");
_Static_assert(_Alignof(wasix_addr_port_t) == 2, "addr_port align");
_Static_assert(offsetof(wasix_addr_port_t, u) == 2, "addr_port union offset");

typedef struct {
	uint8_t tag;
	union {
		uint8_t unspec;
		uint8_t inet4[4];
		uint16_t inet6[8]; // 16 address bytes in network order
	} u;
} wasix_addr_ip_t;

_Static_assert(sizeof(wasix_addr_ip_t) == 18, "addr_ip size");
_Static_assert(offsetof(wasix_addr_ip_t, u) == 2, "addr_ip union offset");

// __wasi_option_timestamp_t: {u8 tag; u8 pad[7]; u64 some}.
typedef struct {
	uint8_t tag;
	uint64_t some;
} wasix_option_timestamp_t;

_Static_assert(sizeof(wasix_option_timestamp_t) == 16, "option_timestamp size");
_Static_assert(offsetof(wasix_option_timestamp_t, some) == 8,
			   "option_timestamp union offset");

// WASIX extension imports. On wasm64 the import names get a "_wasm64" suffix
// and size_t params/outputs are 64-bit, matching the wasm64 WASI ABI.

WASI_EXT_IMPORT("sock_open")
extern __wasi_errno_t __wasiext_sock_open(uint8_t address_family,
										  uint8_t socket_type,
										  uint16_t socket_proto,
										  __wasi_fd_t *out_fd);
WASI_EXT_IMPORT("sock_pair")
extern __wasi_errno_t __wasiext_sock_pair(uint8_t address_family,
										  uint8_t socket_type,
										  uint16_t socket_proto,
										  __wasi_fd_t *out_fd0,
										  __wasi_fd_t *out_fd1);
WASI_EXT_IMPORT("sock_bind")
extern __wasi_errno_t __wasiext_sock_bind(__wasi_fd_t fd,
										  const wasix_addr_port_t *address);
WASI_EXT_IMPORT("sock_listen")
extern __wasi_errno_t __wasiext_sock_listen(__wasi_fd_t fd, size_t backlog);
WASI_EXT_IMPORT("sock_connect")
extern __wasi_errno_t __wasiext_sock_connect(__wasi_fd_t fd,
											 const wasix_addr_port_t *address);
WASI_EXT_IMPORT("sock_accept_v2")
extern __wasi_errno_t __wasiext_sock_accept_v2(__wasi_fd_t fd,
											   __wasi_fdflags_t flags,
											   __wasi_fd_t *out_fd,
											   wasix_addr_port_t *out_address);
WASI_EXT_IMPORT("sock_addr_local")
extern __wasi_errno_t __wasiext_sock_addr_local(__wasi_fd_t fd,
												wasix_addr_port_t *out_address);
WASI_EXT_IMPORT("sock_addr_peer")
extern __wasi_errno_t __wasiext_sock_addr_peer(__wasi_fd_t fd,
											   wasix_addr_port_t *out_address);
WASI_EXT_IMPORT("sock_send_to")
extern __wasi_errno_t __wasiext_sock_send_to(__wasi_fd_t fd,
											 const __wasi_ciovec_t *si_data,
											 size_t si_data_len,
											 __wasi_siflags_t si_flags,
											 const wasix_addr_port_t *address,
											 size_t *out_data_len);
WASI_EXT_IMPORT("sock_recv_from")
extern __wasi_errno_t __wasiext_sock_recv_from(__wasi_fd_t fd,
											   __wasi_iovec_t *ri_data,
											   size_t ri_data_len,
											   __wasi_riflags_t ri_flags,
											   size_t *out_data_len,
											   __wasi_roflags_t *out_flags,
											   wasix_addr_port_t *out_address);
WASI_EXT_IMPORT("sock_set_opt_flag")
extern __wasi_errno_t __wasiext_sock_set_opt_flag(__wasi_fd_t fd,
												  uint8_t option,
												  uint8_t flag);
WASI_EXT_IMPORT("sock_get_opt_flag")
extern __wasi_errno_t __wasiext_sock_get_opt_flag(__wasi_fd_t fd,
												  uint8_t option,
												  uint8_t *out_flag);
WASI_EXT_IMPORT("sock_set_opt_time")
extern __wasi_errno_t
__wasiext_sock_set_opt_time(__wasi_fd_t fd,
							uint8_t option,
							const wasix_option_timestamp_t *timeout);
WASI_EXT_IMPORT("sock_get_opt_time")
extern __wasi_errno_t
__wasiext_sock_get_opt_time(__wasi_fd_t fd,
							uint8_t option,
							wasix_option_timestamp_t *out_timeout);
WASI_EXT_IMPORT("sock_set_opt_size")
extern __wasi_errno_t __wasiext_sock_set_opt_size(__wasi_fd_t fd,
												  uint8_t option,
												  uint64_t size);
WASI_EXT_IMPORT("sock_get_opt_size")
extern __wasi_errno_t __wasiext_sock_get_opt_size(__wasi_fd_t fd,
												  uint8_t option,
												  uint64_t *out_size);
WASI_EXT_IMPORT("sock_send_file")
extern __wasi_errno_t __wasiext_sock_send_file(__wasi_fd_t out_fd,
											   __wasi_fd_t in_fd,
											   uint64_t offset,
											   uint64_t count,
											   uint64_t *out_sent);
WASI_EXT_IMPORT("resolve")
extern __wasi_errno_t __wasiext_resolve(const char *host,
										uint16_t port,
										wasix_addr_ip_t *out_addresses,
										size_t num_addresses,
										size_t *out_num_addresses);

// sockaddr <-> __wasi_addr_port_t conversion.

static int sockaddr_to_wasix(wasix_addr_port_t *out,
							 const struct sockaddr *address,
							 socklen_t address_len) {
	memset(out, 0, sizeof(*out));
	switch (address->sa_family) {
	case AF_INET: {
		if (address_len < (socklen_t)sizeof(struct sockaddr_in)) {
			return EINVAL;
		}
		const struct sockaddr_in *in = (const struct sockaddr_in *)address;
		out->tag = WASIX_AF_INET4;
		out->u.inet4.port = ntohs(in->sin_port);
		memcpy(out->u.inet4.addr, &in->sin_addr, 4);
		return 0;
	}
	case AF_INET6: {
		if (address_len < (socklen_t)sizeof(struct sockaddr_in6)) {
			return EINVAL;
		}
		const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)address;
		out->tag = WASIX_AF_INET6;
		out->u.inet6.port = ntohs(in6->sin6_port);
		memcpy(out->u.inet6.n, in6->sin6_addr.s6_addr, 16);
		out->u.inet6.flow_info1 = (uint16_t)(in6->sin6_flowinfo >> 16);
		out->u.inet6.flow_info0 = (uint16_t)in6->sin6_flowinfo;
		out->u.inet6.scope_id1 = (uint16_t)(in6->sin6_scope_id >> 16);
		out->u.inet6.scope_id0 = (uint16_t)in6->sin6_scope_id;
		return 0;
	}
	default: return EAFNOSUPPORT;
	}
}

// Converts a WASIX addr_port to a POSIX sockaddr; returns the sockaddr size.
static socklen_t wasix_to_sockaddr(const wasix_addr_port_t *in,
								   struct sockaddr *address,
								   socklen_t capacity) {
	switch (in->tag) {
	case WASIX_AF_INET4: {
		if (capacity >= (socklen_t)sizeof(struct sockaddr_in)) {
			struct sockaddr_in *out = (struct sockaddr_in *)address;
			memset(out, 0, sizeof(*out));
			out->sin_family = AF_INET;
			out->sin_port = htons(in->u.inet4.port);
			memcpy(&out->sin_addr, in->u.inet4.addr, 4);
		}
		return sizeof(struct sockaddr_in);
	}
	case WASIX_AF_INET6: {
		if (capacity >= (socklen_t)sizeof(struct sockaddr_in6)) {
			struct sockaddr_in6 *out = (struct sockaddr_in6 *)address;
			memset(out, 0, sizeof(*out));
			out->sin6_family = AF_INET6;
			out->sin6_port = htons(in->u.inet6.port);
			memcpy(out->sin6_addr.s6_addr, in->u.inet6.n, 16);
			out->sin6_flowinfo
				= ((uint32_t)in->u.inet6.flow_info1 << 16)
				  | in->u.inet6.flow_info0;
			out->sin6_scope_id = ((uint32_t)in->u.inet6.scope_id1 << 16)
								 | in->u.inet6.scope_id0;
		}
		return sizeof(struct sockaddr_in6);
	}
	default:
		memset(address, 0, capacity);
		address->sa_family = AF_UNSPEC;
		return sizeof(struct sockaddr);
	}
}

// POSIX socket API.

static int wasix_sock_type(int type) {
	switch (type) {
	case SOCK_STREAM: return WASIX_SOCK_STREAM;
	case SOCK_DGRAM: return WASIX_SOCK_DGRAM;
	default: return -1;
	}
}

static int wasix_proto(int type, int protocol) {
	if (protocol == 0 || protocol == IPPROTO_IP) { return WASIX_PROTO_IP; }
	if (protocol == IPPROTO_TCP && type == SOCK_STREAM) {
		return WASIX_PROTO_TCP;
	}
	if (protocol == IPPROTO_UDP && type == SOCK_DGRAM) {
		return WASIX_PROTO_UDP;
	}
	return -1;
}

int socket(int domain, int type, int protocol) {
	// Strip the flag bits musl allows to be OR'd into the type. SOCK_CLOEXEC is
	// a no-op (WASI has no exec); SOCK_NONBLOCK is applied after creation.
	int nonblocking = type & SOCK_NONBLOCK;
	type &= ~(SOCK_NONBLOCK | SOCK_CLOEXEC);

	int wasix_type = wasix_sock_type(type);
	int proto = wasix_proto(type, protocol);
	if (wasix_type < 0 || proto < 0 || domain == AF_UNIX) {
		errno = EAFNOSUPPORT;
		return -1;
	}

	__wasi_fd_t fd;
	__wasi_errno_t error = __wasiext_sock_open(
		(uint8_t)domain, (uint8_t)wasix_type, (uint16_t)proto, &fd);
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

int socketpair(int domain, int type, int protocol, int sv[2]) {
	(void)protocol;
	int nonblocking = type & SOCK_NONBLOCK;
	type &= ~(SOCK_NONBLOCK | SOCK_CLOEXEC);

	int wasix_type = wasix_sock_type(type);
	if (wasix_type < 0) {
		errno = EOPNOTSUPP;
		return -1;
	}
	if (domain != AF_UNIX && domain != AF_INET && domain != AF_INET6) {
		errno = EAFNOSUPPORT;
		return -1;
	}

	__wasi_fd_t fd0, fd1;
	__wasi_errno_t error = __wasiext_sock_pair(
		(uint8_t)domain, (uint8_t)wasix_type, WASIX_PROTO_IP, &fd0, &fd1);
	if (error != 0) {
		errno = error;
		return -1;
	}
	if (nonblocking) {
		(void)!__wasi_fd_fdstat_set_flags(fd0, __WASI_FDFLAGS_NONBLOCK);
		(void)!__wasi_fd_fdstat_set_flags(fd1, __WASI_FDFLAGS_NONBLOCK);
	}
	sv[0] = fd0;
	sv[1] = fd1;
	return 0;
}

int connect(int socket, const struct sockaddr *address, socklen_t address_len) {
	wasix_addr_port_t wasix_addr;
	int error = sockaddr_to_wasix(&wasix_addr, address, address_len);
	if (error != 0) {
		errno = error;
		return -1;
	}
	error = __wasiext_sock_connect(socket, &wasix_addr);
	if (error != 0) {
		errno = error;
		return -1;
	}
	return 0;
}

int bind(int socket, const struct sockaddr *address, socklen_t address_len) {
	wasix_addr_port_t wasix_addr;
	int error = sockaddr_to_wasix(&wasix_addr, address, address_len);
	if (error != 0) {
		errno = error;
		return -1;
	}
	error = __wasiext_sock_bind(socket, &wasix_addr);
	if (error != 0) {
		errno = error;
		return -1;
	}
	return 0;
}

int listen(int socket, int backlog) {
	if (backlog < 0) { backlog = 0; }
	__wasi_errno_t error = __wasiext_sock_listen(socket, (size_t)backlog);
	if (error != 0) {
		errno = error;
		return -1;
	}
	return 0;
}

int accept4(int socket, struct sockaddr *restrict address,
			socklen_t *restrict address_len, int flags) {
	if (flags & ~(SOCK_NONBLOCK | SOCK_CLOEXEC)) {
		errno = EINVAL;
		return -1;
	}
	if (address != NULL && address_len == NULL) {
		errno = EINVAL;
		return -1;
	}

	wasix_addr_port_t peer_addr;
	__wasi_fd_t new_fd;
	__wasi_errno_t error = __wasiext_sock_accept_v2(
		socket,
		(flags & SOCK_NONBLOCK) ? __WASI_FDFLAGS_NONBLOCK : 0,
		&new_fd,
		&peer_addr);
	if (error != 0) {
		errno = error;
		return -1;
	}

	if (address != NULL) {
		*address_len = wasix_to_sockaddr(&peer_addr, address, *address_len);
	}
	return (int)new_fd;
}

int accept(int socket, struct sockaddr *restrict address,
		   socklen_t *restrict address_len) {
	return accept4(socket, address, address_len, 0);
}

int getsockname(int socket, struct sockaddr *restrict address,
				socklen_t *restrict address_len) {
	wasix_addr_port_t local_addr;
	__wasi_errno_t error = __wasiext_sock_addr_local(socket, &local_addr);
	if (error != 0) {
		errno = error;
		return -1;
	}
	*address_len = wasix_to_sockaddr(&local_addr, address, *address_len);
	return 0;
}

int getpeername(int socket, struct sockaddr *restrict address,
				socklen_t *restrict address_len) {
	wasix_addr_port_t peer_addr;
	__wasi_errno_t error = __wasiext_sock_addr_peer(socket, &peer_addr);
	if (error != 0) {
		errno = error;
		return -1;
	}
	*address_len = wasix_to_sockaddr(&peer_addr, address, *address_len);
	return 0;
}

ssize_t sendto(int socket, const void *buffer, size_t length, int flags,
			   const struct sockaddr *dest_addr, socklen_t dest_len) {
	if (flags & ~(MSG_NOSIGNAL | MSG_DONTWAIT)) {
		errno = EOPNOTSUPP;
		return -1;
	}

	wasix_addr_port_t wasix_addr;
	const wasix_addr_port_t *dest = NULL;
	if (dest_addr != NULL) {
		int error = sockaddr_to_wasix(&wasix_addr, dest_addr, dest_len);
		if (error != 0) {
			errno = error;
			return -1;
		}
		dest = &wasix_addr;
	}

	__wasi_ciovec_t iov = {.buf = buffer, .buf_len = length};
	size_t data_len;
	__wasi_errno_t error = __wasiext_sock_send_to(
		socket,
		&iov,
		1,
		(flags & MSG_DONTWAIT) ? WASIX_SIFLAGS_SEND_DONT_WAIT : 0,
		dest,
		&data_len);
	if (error != 0) {
		errno = error;
		return -1;
	}
	return (ssize_t)data_len;
}

ssize_t send(int socket, const void *buffer, size_t length, int flags) {
	return sendto(socket, buffer, length, flags, NULL, 0);
}

ssize_t recvfrom(int socket, void *restrict buffer, size_t length, int flags,
				 struct sockaddr *restrict address,
				 socklen_t *restrict address_len) {
	if (flags & ~(MSG_PEEK | MSG_WAITALL | MSG_DONTWAIT)) {
		errno = EOPNOTSUPP;
		return -1;
	}
	if (address != NULL && address_len == NULL) {
		errno = EINVAL;
		return -1;
	}

	__wasi_riflags_t ri_flags = (__wasi_riflags_t)(flags & (MSG_PEEK | MSG_WAITALL));
	if (flags & MSG_DONTWAIT) { ri_flags |= WASIX_RIFLAGS_RECV_DONT_WAIT; }

	__wasi_iovec_t iov = {.buf = buffer, .buf_len = length};
	wasix_addr_port_t source_addr;
	size_t data_len;
	__wasi_roflags_t out_flags;
	__wasi_errno_t error = __wasiext_sock_recv_from(
		socket, &iov, 1, ri_flags, &data_len, &out_flags,
		address != NULL ? &source_addr : NULL);
	if (error != 0) {
		errno = error;
		return -1;
	}
	if (address != NULL) {
		*address_len = wasix_to_sockaddr(&source_addr, address, *address_len);
	}
	if (out_flags & MSG_TRUNC) {
		// Preserve the POSIX return convention: the caller learns about
		// truncation only via MSG_TRUNC on recvmsg, so report the full size.
	}
	return (ssize_t)data_len;
}

ssize_t recv(int socket, void *buffer, size_t length, int flags) {
	return recvfrom(socket, buffer, length, flags, NULL, NULL);
}

// POSIX sendfile() over WASIX sock_send_file. sock_send_file always reads at
// an absolute file offset without touching in_fd's position, so a NULL offset
// is emulated by saving and restoring the position.
ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count) {
	uint64_t file_offset;
	if (offset != NULL) {
		file_offset = (uint64_t)*offset;
	} else {
		__wasi_errno_t error = __wasi_fd_tell(in_fd, &file_offset);
		if (error != 0) {
			errno = error;
			return -1;
		}
	}

	uint64_t num_sent = 0;
	__wasi_errno_t error = __wasiext_sock_send_file(
		out_fd, in_fd, file_offset, count, &num_sent);
	if (error != 0) {
		errno = error;
		return -1;
	}

	if (offset != NULL) {
		*offset = (off_t)(file_offset + num_sent);
	} else {
		__wasi_filesize_t new_offset;
		(void)!__wasi_fd_seek(
			in_fd, (int64_t)num_sent, __WASI_WHENCE_CUR, &new_offset);
	}
	return (ssize_t)num_sent;
}

// Socket options. Maps POSIX (level, optname) pairs to a WASIX option tag and
// its value kind: 0 = flag, 1 = size, 2 = time, 3 = read-only flag,
// 4 = read-only size.
static int wasix_option(int level, int optname, int *kind) {
	if (level == SOL_SOCKET) {
		switch (optname) {
		case SO_REUSEADDR: *kind = 0; return WASIX_OPT_REUSE_ADDR;
		case SO_BROADCAST: *kind = 0; return WASIX_OPT_BROADCAST;
		case SO_KEEPALIVE: *kind = 0; return WASIX_OPT_KEEP_ALIVE;
#ifdef SO_DONTROUTE
		case SO_DONTROUTE: *kind = 0; return WASIX_OPT_DONT_ROUTE;
#endif
#ifdef SO_OOBINLINE
		case SO_OOBINLINE: *kind = 0; return WASIX_OPT_OOB_INLINE;
#endif
#ifdef SO_REUSEPORT
		case SO_REUSEPORT: *kind = 0; return WASIX_OPT_REUSE_PORT;
#endif
#ifdef SO_LINGER
		case SO_LINGER: *kind = 2; return WASIX_OPT_LINGER;
#endif
		case SO_SNDBUF: *kind = 1; return WASIX_OPT_SEND_BUF_SIZE;
		case SO_RCVBUF: *kind = 1; return WASIX_OPT_RECV_BUF_SIZE;
#ifdef SO_SNDLOWAT
		case SO_SNDLOWAT: *kind = 1; return WASIX_OPT_SEND_LOWAT;
#endif
#ifdef SO_RCVLOWAT
		case SO_RCVLOWAT: *kind = 1; return WASIX_OPT_RECV_LOWAT;
#endif
#ifdef SO_RCVTIMEO
		case SO_RCVTIMEO: *kind = 2; return WASIX_OPT_RECV_TIMEOUT;
#endif
#ifdef SO_SNDTIMEO
		case SO_SNDTIMEO: *kind = 2; return WASIX_OPT_SEND_TIMEOUT;
#endif
		case SO_ACCEPTCONN: *kind = 3; return WASIX_OPT_LISTENING;
		case SO_ERROR: *kind = 3; return WASIX_OPT_LAST_ERROR;
		case SO_TYPE: *kind = 4; return WASIX_OPT_TYPE;
		case SO_PROTOCOL: *kind = 4; return WASIX_OPT_PROTO;
		default: return -1;
		}
	}
	if ((level == IPPROTO_TCP || level == SOL_TCP) && optname == TCP_NODELAY) {
		*kind = 0;
		return WASIX_OPT_NO_DELAY;
	}
	if ((level == IPPROTO_IPV6 || level == SOL_IPV6) && optname == IPV6_V6ONLY) {
		*kind = 0;
		return WASIX_OPT_ONLY_V6;
	}
#ifdef IP_TTL
	if ((level == IPPROTO_IP || level == SOL_IP) && optname == IP_TTL) {
		*kind = 1;
		return WASIX_OPT_TTL;
	}
#endif
#ifdef IP_MULTICAST_TTL
	if ((level == IPPROTO_IP || level == SOL_IP) && optname == IP_MULTICAST_TTL) {
		*kind = 1;
		return WASIX_OPT_MULTICAST_TTL_V4;
	}
#endif
#ifdef IP_MULTICAST_LOOP
	if ((level == IPPROTO_IP || level == SOL_IP) && optname == IP_MULTICAST_LOOP) {
		*kind = 0;
		return WASIX_OPT_MULTICAST_LOOP_V4;
	}
#endif
	return -1;
}

int setsockopt(int socket, int level, int option_name,
			   const void *option_value, socklen_t option_len) {
	int kind;
	int option = wasix_option(level, option_name, &kind);
	if (option < 0 || kind >= 3) {
		errno = ENOPROTOOPT;
		return -1;
	}

	__wasi_errno_t error;
	switch (kind) {
	case 0: { // flag
		if (option_len < (socklen_t)sizeof(int)) {
			errno = EINVAL;
			return -1;
		}
		error = __wasiext_sock_set_opt_flag(
			socket, (uint8_t)option,
			*(const int *)option_value != 0 ? 1 : 0);
		break;
	}
	case 1: { // size
		if (option_len < (socklen_t)sizeof(int)) {
			errno = EINVAL;
			return -1;
		}
		error = __wasiext_sock_set_opt_size(
			socket, (uint8_t)option, (uint64_t)*(const int *)option_value);
		break;
	}
	default: { // time
		wasix_option_timestamp_t timeout;
		memset(&timeout, 0, sizeof(timeout));
		if (option_name == SO_LINGER) {
			const struct linger *l = (const struct linger *)option_value;
			if (option_len < (socklen_t)sizeof(*l)) {
				errno = EINVAL;
				return -1;
			}
			if (l->l_onoff) {
				timeout.tag = WASIX_OPTION_SOME;
				timeout.some = (uint64_t)l->l_linger * 1000000000ull;
			}
		} else {
			const struct timeval *tv = (const struct timeval *)option_value;
			if (option_len < (socklen_t)sizeof(*tv)) {
				errno = EINVAL;
				return -1;
			}
			if (tv->tv_sec != 0 || tv->tv_usec != 0) {
				timeout.tag = WASIX_OPTION_SOME;
				timeout.some = (uint64_t)tv->tv_sec * 1000000000ull
							   + (uint64_t)tv->tv_usec * 1000ull;
			}
		}
		error = __wasiext_sock_set_opt_time(socket, (uint8_t)option, &timeout);
		break;
	}
	}
	if (error != 0) {
		errno = error;
		return -1;
	}
	return 0;
}

int getsockopt(int socket, int level, int option_name,
			   void *restrict option_value, socklen_t *restrict option_len) {
	int kind;
	int option = wasix_option(level, option_name, &kind);
	if (option < 0) {
		errno = ENOPROTOOPT;
		return -1;
	}

	uint64_t value = 0;
	__wasi_errno_t error;
	switch (kind) {
	case 0:
	case 3: { // flag
		uint8_t flag = 0;
		error = __wasiext_sock_get_opt_flag(socket, (uint8_t)option, &flag);
		value = flag;
		break;
	}
	case 1:
	case 4: { // size
		error = __wasiext_sock_get_opt_size(socket, (uint8_t)option, &value);
		if (error == 0 && option == WASIX_OPT_TYPE) {
			// WASIX reports its own socket type constants; translate back to
			// the SOCK_* values (which equal the WASI filetype values).
			value = value == WASIX_SOCK_STREAM ? SOCK_STREAM
					: value == WASIX_SOCK_DGRAM ? SOCK_DGRAM
												: 0;
		}
		break;
	}
	default: { // time
		wasix_option_timestamp_t timeout;
		error = __wasiext_sock_get_opt_time(socket, (uint8_t)option, &timeout);
		if (error != 0) {
			errno = error;
			return -1;
		}
		if (option == WASIX_OPT_LINGER) {
			struct linger l;
			l.l_onoff = timeout.tag == WASIX_OPTION_SOME;
			l.l_linger = (int)(timeout.some / 1000000000ull);
			memcpy(option_value, &l,
				   *option_len < (socklen_t)sizeof(l) ? (size_t)*option_len
													  : sizeof(l));
			*option_len = sizeof(l);
			return 0;
		}
		struct timeval tv;
		tv.tv_sec = (time_t)(timeout.some / 1000000000ull);
		tv.tv_usec = (suseconds_t)((timeout.some % 1000000000ull) / 1000ull);
		memcpy(option_value, &tv,
			   *option_len < (socklen_t)sizeof(tv) ? (size_t)*option_len
												   : sizeof(tv));
		*option_len = sizeof(tv);
		return 0;
	}
	}
	if (error != 0) {
		errno = error;
		return -1;
	}

	int int_value = (int)value;
	memcpy(option_value, &int_value,
		   *option_len < (socklen_t)sizeof(int) ? (size_t)*option_len
												: sizeof(int));
	*option_len = sizeof(int);
	return 0;
}

// Name resolution via the WASIX resolve() import. resolve() fills an array of
// 18-byte __wasi_addr_ip_t records; port is a host-order hint returned in the
// generated addrinfos.

static struct addrinfo *make_addrinfo(int tag, const uint8_t *ip,
									  uint16_t port, int socktype,
									  const struct addrinfo *hint) {
	struct addrinfo *ai = calloc(1, sizeof(*ai));
	if (ai == NULL) { return NULL; }

	struct sockaddr_storage *ss = calloc(1, sizeof(*ss));
	if (ss == NULL) {
		free(ai);
		return NULL;
	}

	ai->ai_flags = hint ? hint->ai_flags : 0;
	ai->ai_socktype = socktype;
	ai->ai_protocol
		= socktype == SOCK_STREAM ? IPPROTO_TCP
		  : socktype == SOCK_DGRAM ? IPPROTO_UDP
								   : 0;

	if (tag == WASIX_AF_INET4) {
		struct sockaddr_in *in = (struct sockaddr_in *)ss;
		in->sin_family = AF_INET;
		in->sin_port = htons(port);
		memcpy(&in->sin_addr, ip, 4);
		ai->ai_family = AF_INET;
		ai->ai_addrlen = sizeof(*in);
	} else {
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)ss;
		in6->sin6_family = AF_INET6;
		in6->sin6_port = htons(port);
		memcpy(in6->sin6_addr.s6_addr, ip, 16);
		ai->ai_family = AF_INET6;
		ai->ai_addrlen = sizeof(*in6);
	}
	ai->ai_addr = (struct sockaddr *)ss;
	return ai;
}

void freeaddrinfo(struct addrinfo *res) {
	while (res != NULL) {
		struct addrinfo *next = res->ai_next;
		free(res->ai_addr);
		free(res);
		res = next;
	}
}

int getaddrinfo(const char *restrict host, const char *restrict serv,
				const struct addrinfo *restrict hint,
				struct addrinfo **restrict res) {
	*res = NULL;

	int flags = hint ? hint->ai_flags : 0;
	int family = hint ? hint->ai_family : AF_UNSPEC;
	if (family != AF_UNSPEC && family != AF_INET && family != AF_INET6) {
		return EAI_FAMILY;
	}
	int socktype = hint ? hint->ai_socktype : 0;
	if (socktype != 0 && socktype != SOCK_STREAM && socktype != SOCK_DGRAM) {
		return EAI_SOCKTYPE;
	}
	if (host == NULL && serv == NULL) { return EAI_NONAME; }

	uint16_t port = 0;
	if (serv != NULL) {
		char *end;
		long parsed = strtol(serv, &end, 10);
		if (*serv == '\0' || *end != '\0' || parsed < 0 || parsed > 65535) {
			return EAI_NONAME;
		}
		port = (uint16_t)parsed;
	}

	// Resolve the host to a list of WASIX addr_ip records. Numeric literals
	// and NULL (wildcard/loopback) are handled locally; only real hostnames
	// go through the resolver import.
	wasix_addr_ip_t addresses[16];
	size_t num_addresses = 0;

	struct in_addr a4;
	struct in6_addr a6;
	if (host == NULL) {
		if (family != AF_INET6) {
			static const uint8_t any4[4] = {0, 0, 0, 0};
			static const uint8_t loopback4[4] = {127, 0, 0, 1};
			addresses[num_addresses].tag = WASIX_AF_INET4;
			memcpy(addresses[num_addresses].u.inet4,
				   (flags & AI_PASSIVE) ? any4 : loopback4, 4);
			num_addresses++;
		}
		if (family != AF_INET) {
			addresses[num_addresses].tag = WASIX_AF_INET6;
			memcpy(addresses[num_addresses].u.inet6,
				   (flags & AI_PASSIVE) ? in6addr_any.s6_addr
										: in6addr_loopback.s6_addr,
				   16);
			num_addresses++;
		}
	} else if (inet_pton(AF_INET, host, &a4) == 1) {
		if (family == AF_INET6) { return EAI_NONAME; }
		addresses[num_addresses].tag = WASIX_AF_INET4;
		memcpy(addresses[num_addresses].u.inet4, &a4, 4);
		num_addresses++;
	} else if (inet_pton(AF_INET6, host, &a6) == 1) {
		if (family == AF_INET) { return EAI_NONAME; }
		addresses[num_addresses].tag = WASIX_AF_INET6;
		memcpy(addresses[num_addresses].u.inet6, &a6, 16);
		num_addresses++;
	} else {
		if (flags & AI_NUMERICHOST) { return EAI_NONAME; }
		__wasi_errno_t error = __wasiext_resolve(
			host, port, addresses, 16, &num_addresses);
		if (error != 0) {
			switch (error) {
			case EAGAIN: return EAI_AGAIN;
			case ENOMEM: return EAI_MEMORY;
			case EACCES:
				errno = EACCES;
				return EAI_SYSTEM;
			default: return EAI_NONAME;
			}
		}
	}
	if (num_addresses == 0) { return EAI_NONAME; }

	struct addrinfo *result = NULL;
	struct addrinfo **tail = &result;
	for (size_t i = 0; i < num_addresses; i++) {
		int types[2];
		int num_types;
		if (socktype != 0) {
			types[0] = socktype;
			num_types = 1;
		} else {
			types[0] = SOCK_STREAM;
			types[1] = SOCK_DGRAM;
			num_types = 2;
		}
		const uint8_t *ip = addresses[i].tag == WASIX_AF_INET4
								? addresses[i].u.inet4
								: (const uint8_t *)addresses[i].u.inet6;
		for (int t = 0; t < num_types; t++) {
			struct addrinfo *ai = make_addrinfo(
				addresses[i].tag, ip, port, types[t], hint);
			if (ai == NULL) {
				freeaddrinfo(result);
				return EAI_MEMORY;
			}
			*tail = ai;
			tail = &ai->ai_next;
		}
	}

	*res = result;
	return 0;
}
