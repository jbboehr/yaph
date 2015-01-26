/***************************************************************************
                          tcp_utils.c  -  utilities
                             -------------------
    begin                : Sun Dec 29 2002
    copyright             : (C) 2002 by Proxy Labs (www.proxylabs.com)
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

#include "yaph.h"

int connect_socket(struct sockaddr_in *target)
{
  int sock;
 sock=socket(AF_INET,SOCK_STREAM,0);
  if(sock==-1)
    goto error;
  if(-1==timed_connect(sock,(struct sockaddr *)target,sizeof(struct sockaddr)) )
    goto error;
  return sock;
error:
  return -1;
}

int read_line(int fd, char *buff, size_t size)
{
  int i,ready;
  struct pollfd pfd[1];

  pfd[0].fd=fd;
  pfd[0].events=POLLIN;
  for(i=0;i<size-1;i++)
  {
    pfd[0].revents=0;
    ready=poll(pfd,1,globals->tcp_read_time_out);
    if(ready!=1 || !(pfd[0].revents&POLLIN) || 1!=read(fd,&buff[i],1))
      return READ_LINE_ERROR_READ_FD;
    else if(buff[i]=='\n')
    {
        buff[i+1]=0;
        return (i+1);
    }
  }
  return READ_LINE_ERROR_SIZE_EXCEEDED;
}

int read_n_bytes(int fd,char *buff, size_t size)
{
  int i,ready;
  struct pollfd pfd[1];

  pfd[0].fd=fd;
  pfd[0].events=POLLIN;
  for(i=0;i<size;i++)
  {
    pfd[0].revents=0;
    ready=poll(pfd,1,globals->tcp_read_time_out);
    if(ready!=1 || !(pfd[0].revents&POLLIN) || 1!=read(fd,&buff[i],1))
      return READ_N_BYTES_ERROR_READ_FD;
  }
  return size;
}

int read_until_close(int fd, char *buff,size_t size)
{
  int i;
  for (i=0;i<size-1;i++)
  {
       if(1!=read_n_bytes(fd,&buff[i],1))
          break;
  }
  buff[++i]=0;
  return i;
}

int write_n_bytes(int fd,char *buff,size_t size)
{
  int i=0,wrote=0;
  for(;;)
  {
    i=send(fd,&buff[wrote],size-wrote,0);
    if(i<=0)
         return i;
    wrote+=i;
    if(wrote==size)
        return wrote;
  }
}

int timed_connect(int sock, const struct sockaddr *addr, socklen_t len)
{
	int ret,value,value_len;
 	struct pollfd pfd[1];

	pfd[0].fd=sock;
	pfd[0].events=POLLOUT;	
	fcntl(sock, F_SETFL, O_NONBLOCK);
  	ret=connect(sock, addr,  len);
  	if(ret==-1 && errno==EINPROGRESS)
   	{
    		ret=poll(pfd,1,globals->tcp_connect_time_out);
      		if(ret==1)
        	{
           		value_len=sizeof(int);
             		getsockopt(sock,SOL_SOCKET,SO_ERROR,&value,&value_len) ;
               	if(!value)
               		ret=0;
                 	else
                  		ret=-1;
           	}
              else
              	ret=-1;
       }
       else if(ret==0)
       	;
        else
       	ret=-1;
       	

       fcntl(sock, F_SETFL, !O_NONBLOCK);
       return ret;
}
