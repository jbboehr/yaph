/***************************************************************************
                          functions.h  -  description
                             -------------------
    begin                : Sun Dec 29 2002
    copyright           : (C) 2002 by Proxy Labs (www.proxylabs.com)
    email                : yaph@proxylabs.com
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

//----  init
void check_nmap_state();
void init_options(int argc, char *argv[]);
void init_engine();

//--- tcp_utils
int connect_socket(struct sockaddr_in *target);
int read_line(int fd, char *buff, size_t size);
int read_n_bytes(int fd,char *buff, size_t size);
int read_until_close(int fd, char *buff,size_t size);
int write_n_bytes(int fd,char *buff,size_t size);
int timed_connect(int sock, const struct sockaddr *addr, socklen_t len);

//-- content_utils
int is_valid_content(int fd);
int get_target( target_st * target);
int read_pipe_line(int fd, char *buff, size_t size);
void c2bin(const char *in, char *out);
void bank_put( struct sockaddr_in * node);
struct sockaddr_in * bank_get();
void bank_init();

//-- threads
void *check_socks5(void *arg);
void *check_socks4(void *arg);
void *check_http(void *arg);
void * nmap_parser_thread(void *arg);
void * file_parser_thread(void *arg);
void init_check(void * (*func)(void *),struct sockaddr_in *addr);

//-- log
int write_log(int level,char* file, char* func, int line,char *str,...);

