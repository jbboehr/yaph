/***************************************************************************
                          definitions.h  -  description
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

//-- errcodes
#define READ_LINE_ERROR_READ_FD -1
#define READ_LINE_ERROR_SIZE_EXCEEDED -2

#define READ_N_BYTES_ERROR_READ_FD -1

//-- buffers
#define BUFF_SIZ (1024*10)
#define CONTENT_BUFF_SIZ (1024*256)
#define BUFF_TARGET_SIZ 100
#define BUFF_HOST_SIZ 20
#define BUFF_PORT_SIZ 7

// log line
#define  FFL __FILE__, __FUNCTION__ , __LINE__

//-- macros
#define exit_error(x)   {\
FILE *f=NULL;\
int sig=SIGKILL;\
char d_stamp[100];\
struct tm tm;\
time_t t;\
if(globals->log_file_f)\
   f=globals->log_file_f;\
else\
   f=stderr;\
t=time(NULL);\
localtime_r(&t,&tm);\
strftime(d_stamp,99,"%a %d/%b %H:%M:%S",&tm);\
fprintf(f,"[%s]:%s:%s:%d:FATAL ERROR: %s , errno=%d\n",d_stamp,FFL,strerror(x),x);\
fflush(f);\
if(globals && globals->nmap_pid)\
 kill(globals->nmap_pid,sig);\
kill(0,sig);\
exit(x);}

//-- version
#define YAPH_VERSION "0.91"



typedef enum {  NMAP_E=0,HUNTER_FILE_E,OUR_FILE_E} engine_type;
//-- structures
typedef struct bank_node_st
{
   struct sockaddr_in addr;
   struct bank_node_st * next;
} bank_node;

typedef struct global_st
{
   char ** nmap_string;
   char *content_host;
   char *content_data;
   char *content_request;
   int debug_level;
   int content_port;
   pthread_mutex_t mutex;
   pid_t nmap_pid;
   int target_output_fd;
   int target_input_fd;
   int nmap_output_fd;
   int nmap_input_fd;
   int tcp_read_time_out;
   int tcp_connect_time_out;
   FILE * result_f;
   FILE * log_file_f;
   engine_type et;
   sem_t check_sem;
   int paral_checks;
   bank_node *bank;
}  global_data;

typedef enum {  ALL_TYPES=0,HTTP_TYPE,SOCKS4_TYPE,SOCKS5_TYPE } check_type;
typedef struct
{
struct sockaddr_in target_addr;
check_type	type;
} target_st;

// some defaults
#define CONTENT_PORT 80
#define CONTENT_HOST "www.yahoo.com"
#define CONTENT_DATA "search.yahoo.com"
#define CONTENT_REQUEST  "GET / HTTP/1.0\r\n\r\n"
