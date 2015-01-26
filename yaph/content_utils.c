/***************************************************************************
                          content_utils.c  -  utilities
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

#include "yaph.h"

int is_valid_content(int fd)
{
  char buff[CONTENT_BUFF_SIZ];
  sprintf( buff,globals->content_request);
  write_log(3,FFL,"Trying to validate proxy channel ..");
  if(strlen(buff)!=write_n_bytes(fd,buff,strlen(buff)))
     return 0;
  if(0<read_until_close(fd,buff,sizeof(buff)))
  if (strstr(buff,globals->content_data)) //pattern found in result
      return 1;
  return 0;
}

int get_target( target_st * target)
{
  char buff[BUFF_SIZ];
  int read_bytes,type=0;
  char string_ip[BUFF_HOST_SIZ];
  int port=0;
  read_bytes=read_pipe_line(globals->target_output_fd,buff,sizeof(buff));
  if(read_bytes==-1)
    return -1;
  memset(target,0,sizeof(target_st));
  memset(string_ip,0,sizeof(string_ip));
  sscanf(buff,"%s %d %d",string_ip,&port,&type);
  write_log(4,FFL,"Got target at %s:%d tcp",string_ip,port);
  target->type=type;
  target->target_addr.sin_family=AF_INET;
  target->target_addr.sin_port=htons(port);
  target->target_addr.sin_addr.s_addr=inet_addr(string_ip);
  return 0;
}

int read_pipe_line(int fd, char *buff, size_t size)
{
  int i;

  for(i=0;i<size-1;i++)
  {
    if(1!=read(fd,&buff[i],1))
      return READ_LINE_ERROR_READ_FD;
    else if(buff[i]=='\n')
    {
        buff[i+1]=0;
        return (i+1);
    }
  }
  return READ_LINE_ERROR_SIZE_EXCEEDED;
}


void c2bin(const char *in, char *out)
{
	char s16[3];
	char s8[4];
	int i,j,l;

	s16[2]=0;
	s8[3]=0;
	l=strlen(in);

	for(i=0,j=0;i<l;i++,j++){
		if(in[i]=='\\'){
			switch(in[i+1]){
			case 'a':
				out[j]='\a';
				i++;
				break;
			case 'b':
				out[j]='\b';
				i++;
				break;
			case 'f':
				out[j]='\f';
				i++;
				break;
			case 'n':
				out[j]='\n';
				i++;
				break;
			case 'r':
				out[j]='\r';
				i++;
				break;
			case 't':
				out[j]='\t';
				i++;
				break;
			case 'v':
				out[j]='\v';
				i++;
				break;
			case '\\':
				out[j]='\\';
				i++;
				break;
			case '\?':
				out[j]='\?';
				i++;
				break;
			case '\'':
				out[j]='\'';
				i++;
				break;
			case '\"':
				out[j]='\"';
				i++;
				break;
			case 'X':
			case 'x':
				strncpy(s16,in+i+2,2);
				out[j]=(char)strtol(s16,NULL,16);
				i+=3;
				break;
			case '0':
				out[j]=0;
				i++;
				break;
			default:
				//format error, skip:
				j--;
			}
				

		}else {
			out[j]=in[i];
		}
	}
	out[j]=0;
}

void bank_init()
{
 bank_node *tmp=NULL;
 int i;
 tmp=malloc(sizeof(bank_node)*globals->paral_checks);
 if(!tmp)
     exit_error(errno);
 globals->bank=NULL;
 for(i=0;i<globals->paral_checks;i++)
   bank_put( (struct sockaddr_in *)&tmp[i] );
}

struct sockaddr_in * bank_get()
{
   bank_node *tmp=NULL;
   pthread_mutex_lock(&(globals->mutex));
   tmp=globals->bank;
   globals->bank=globals->bank->next;
   pthread_mutex_unlock(&(globals->mutex));
   return (struct sockaddr_in *)tmp;
}

void bank_put( struct sockaddr_in * node)
{
  pthread_mutex_lock(&(globals->mutex));
  ((bank_node*)node)->next=globals->bank;
  globals->bank=(bank_node*)node;
  pthread_mutex_unlock(&(globals->mutex));
}
