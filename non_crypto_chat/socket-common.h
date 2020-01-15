/*
 * socket-common.h
 *
 * Simple TCP/IP communication using sockets
 *
 * Anastasis Stathopoulos <anas.stathop@gmail.com>
 */

#ifndef _SOCKET_COMMON_H
#define _SOCKET_COMMON_H

/* Compile-time options */
#define TCP_PORT    35001
#define TCP_BACKLOG 5


#define CYAN 	"\033[0;36m"
#define RESET 	"\033[0m"


#define DATA_SIZE       256
#define KEY_SIZE		16  /* AES128 */


#endif /* _SOCKET_COMMON_H */
