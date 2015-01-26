/***************************************************************************
                          threads.c  -  thread functions
                             -------------------
    begin                : Sun Dec 29 2002
    copyright            : (C) 2002 by Proxy Labs (www.proxylabs.com)
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

void *check_socks4(void *arg)
{
  struct sockaddr_in * target = (struct sockaddr_in *) arg;
  int sock;
    int addr,port;
  char buff[BUFF_SIZ];
  pthread_detach(pthread_self());
  write_log(2,FFL,"Socks4 proxy test STARTED against %s:%d tcp",
	inet_ntoa(target->sin_addr),
	ntohs(target->sin_port));
  sock=connect_socket(target);
  if(sock==-1)
  {
    write_log(3,FFL,"Can't connect to %s:%d : %s , errno=%d",
          inet_ntoa(target->sin_addr),ntohs(target->sin_port),strerror(errno),errno);
    goto done;  // we done here.
  }
  buff[0]=4; // socks version
  buff[1]=1; // connect command
  addr=inet_addr(globals->content_host);
  port=htons(globals->content_port);
  memcpy(&buff[2],&port,2); // dest port
  memcpy(&buff[4],&addr,4); // dest host
  buff[8]=0; // username
  if(9!=write_n_bytes(sock,buff,9))
  {
    write_log(3,FFL,"It seems %s:%d tcp remote side closed on write attempt .... %s , errno=%d",
          inet_ntoa(target->sin_addr),ntohs(target->sin_port),strerror(errno),errno);
    goto done;  // we done here.
  }

 write_log(3,FFL,"Trying to set up  tunnel via %s:%d tcp, Socks4 command sent",
              inet_ntoa(target->sin_addr),ntohs(target->sin_port));
 	
  memset(buff,0,sizeof(buff));

	if(8!=read_n_bytes(sock,buff,8))
 	{
		write_log(3,FFL,"Bad response from %s:%d tcp, server closed or timeout hit.... %s , errno=%d",
			inet_ntoa(target->sin_addr),ntohs(target->sin_port),strerror(errno),errno);
		goto done;  // we done here.
  	}

	
	if (buff[0]!=0||buff[1]!=90)
      {
		write_log(3,FFL,"Server denied to set up tunnel");
		goto done;
	}
	else
	{
		write_log(3,FFL,"Server accepted to set tunnel");
	}

	if(is_valid_content(sock))
	{
      	 write_log(2,FFL,"VALIDATED %s:%d  as Socks4 proxy server",
			inet_ntoa(target->sin_addr),ntohs(target->sin_port));

      	     fprintf(globals->result_f,"socks4 %s %d\n",inet_ntoa(target->sin_addr),ntohs(target->sin_port));
	
	}
	else
	{
	      write_log(3,FFL,"Failed to validate tunnel ...");
      	goto done;
	}

		
done:	
  write_log(2,FFL,"Socks4 proxy test FINISHED against %s:%d tcp",
        inet_ntoa(target->sin_addr),
        ntohs(target->sin_port));
  close(sock);
  bank_put(target);
  sem_post(&globals->check_sem);	
  return 0;
}

void *check_socks5(void *arg)
{

 struct sockaddr_in * target = (struct sockaddr_in *) arg;
  int sock,len;
  int addr,port;
  char buff[BUFF_SIZ];
  pthread_detach(pthread_self());
  write_log(2,FFL,"Socks5 proxy test STARTED against %s:%d tcp",
	inet_ntoa(target->sin_addr),
	ntohs(target->sin_port));
  sock=connect_socket(target);
  if(sock==-1)
  {
    write_log(3,FFL,"Can't connect to %s:%d : %s , errno=%d",
          inet_ntoa(target->sin_addr),ntohs(target->sin_port),strerror(errno),errno);
    goto done;  // we done here.
  }

  buff[0]=5;   //version
  buff[1]=1;	//nomber of methods
  buff[2]=0;   // no auth method

  if(3!=write_n_bytes(sock,buff,3))
  {
    write_log(3,FFL,"It seems %s:%d tcp remote side closed on write attempt .... %s , errno=%d",
          inet_ntoa(target->sin_addr),ntohs(target->sin_port),strerror(errno),errno);
    goto done;  // we done here.
  }

  write_log(3,FFL,"Trying to set up  tunnel via %s:%d tcp, Socks5 'method' command sent",
              inet_ntoa(target->sin_addr),ntohs(target->sin_port));
 	
  memset(buff,0,sizeof(buff));

	if(2!=read_n_bytes(sock,buff,2))
 	{
		write_log(3,FFL,"It seems %s:%d tcp server closed or timeout hit.... %s , errno=%d",
			inet_ntoa(target->sin_addr),ntohs(target->sin_port),strerror(errno),errno);
		goto done;  // we done here.
  	}
			
      if (buff[1])
      {
        write_log(3,FFL,"Bad response from %s:%d tcp, for Socks5 'method' command ....",
			inet_ntoa(target->sin_addr),ntohs(target->sin_port));
        goto done;
      }

      buff[0]=5;       // version
	buff[1]=1;       // connect
	buff[2]=0;       // reserved
	buff[3]=1;       // ip v4
 	addr=inet_addr(globals->content_host);
	port=htons(globals->content_port);
	memcpy(&buff[4],&addr,4); // dest host
 	memcpy(&buff[8],&port,2); // dest port

      if(10!=write_n_bytes(sock,buff,10))
	{
		write_log(3,FFL,"It seems %s:%d tcp remote side closed on write attempt .... %s , errno=%d",
		inet_ntoa(target->sin_addr),ntohs(target->sin_port),strerror(errno),errno);
		goto done;  // we done here.
	}

	write_log(3,FFL,"..... Trying to set up  tunnel via %s:%d tcp, Socks5 'connect' command sent",
              inet_ntoa(target->sin_addr),ntohs(target->sin_port));

       if(4!=read_n_bytes(sock,buff,4))
 	{
		write_log(3,FFL,"Bad response from %s:%d tcp server closed or timeout hit.... %s , errno=%d",
			inet_ntoa(target->sin_addr),ntohs(target->sin_port),strerror(errno),errno);
		goto done;  // we done here.
  	}
			
			

	if (buff[0]!=5||buff[1]!=0)
      {
           write_log(3,FFL,"Bad response from %s:%d tcp, for Socks5 'connect' command ....",
			inet_ntoa(target->sin_addr),ntohs(target->sin_port));
	     goto done;
      }
	
			
   	switch (buff[3])
      {
		case 1: len=4;  break;
		case 4: len=16; break;
		case 3: len=0;
  			if(1!=read_n_bytes(sock,(char*)&len,1))
 			{
				write_log(3,FFL,"It seems %s:%d tcp server closed or timeout hit.... %s , errno=%d",
					inet_ntoa(target->sin_addr),ntohs(target->sin_port),strerror(errno),errno);
				goto done;  // we done here.
		  	}
     			break;
		default:
			write_log(3,FFL,"Bad response from %s:%d tcp, for Socks5 'connect' command ....",
				inet_ntoa(target->sin_addr),ntohs(target->sin_port));
		     goto done;
	}
			
      if((len+2)!=read_n_bytes(sock,buff,(len+2)))
 	{
		write_log(3,FFL,"It seems %s:%d tcp server closed or timeout hit.... %s , errno=%d",
			inet_ntoa(target->sin_addr),ntohs(target->sin_port),strerror(errno),errno);
		goto done;  // we done here.
	}

      write_log(3,FFL,"Server accepted to set tunnel");
	
	if(is_valid_content(sock))
	{
            write_log(2,FFL,"VALIDATED %s:%d  as Socks5 proxy server",
			inet_ntoa(target->sin_addr),ntohs(target->sin_port));
       	
             fprintf(globals->result_f,"socks5 %s %d\n",inet_ntoa(target->sin_addr),ntohs(target->sin_port));
	
	}
	else
	{
	      write_log(3,FFL,"Failed to validate tunnel ...");
      	goto done;
	}



done:	
  write_log(2,FFL,"Socks5 proxy test FINISHED against %s:%d tcp",
        inet_ntoa(target->sin_addr),
        ntohs(target->sin_port));
  close(sock);
  bank_put(target);
  sem_post(&globals->check_sem);	
  return 0;
}


void *check_http(void *arg)
{
  struct sockaddr_in * target = (struct sockaddr_in *) arg;
  int sock,len;
  char buff[BUFF_SIZ];
  pthread_detach(pthread_self());
  write_log(2,FFL,"http-connect proxy test STARTED against %s:%d tcp",
        inet_ntoa(target->sin_addr),
        ntohs(target->sin_port));
  memset(buff,0,sizeof(buff));
  sock=connect_socket(target);
  if(sock==-1)
  {
    write_log(3,FFL,"Can't connect to %s:%d : %s , errno=%d",
          inet_ntoa(target->sin_addr),ntohs(target->sin_port),strerror(errno),errno);
    goto done;  // we done here.
  }


  sprintf( buff,"CONNECT %s:%d HTTP/1.0\r\nUser-Agent: yaph-%s\r\n\r\n",
             globals->content_host,
             globals->content_port,
            YAPH_VERSION);
  len=strlen(buff);
  if(len!=send(sock,buff,len,0))
  {
    write_log(3,FFL,"It seems %s:%d tcp remote side closed on write attempt .... %s , errno=%d",
          inet_ntoa(target->sin_addr),ntohs(target->sin_port),strerror(errno),errno);
    goto done;  // we done here.
  }

 write_log(3,FFL,"Trying to set up http tunnel via %s:%d tcp. HTTP-CONNECT command sent.",
              inet_ntoa(target->sin_addr),ntohs(target->sin_port));

 if(0>read_line(sock,buff,sizeof(buff)))
  {
   write_log(3,FFL,"Server does not reply - server closed or timeout hit");
   goto done;
  }

 if(!strstr(buff,"200") )
 {
   write_log(3,FFL,"Server denied to set up http tunnel : %s",buff);
   goto done;
 }
 else
 {
   write_log(3,FFL,"Server accepted to set up http tunnel : %s",buff);
 }

 if(is_valid_content(sock))
 {
       write_log(2,FFL,"VALIDATED %s:%d  as http-connect proxy server",
			inet_ntoa(target->sin_addr),ntohs(target->sin_port));

      fprintf(globals->result_f,"http %s %d\n",inet_ntoa(target->sin_addr),ntohs(target->sin_port));

 }
 else
 {
      write_log(3,FFL,"Failed to validate tunnel ...");
      goto done;
 }

done:
  write_log(2,FFL,"http-connect proxy test FINISHED against %s:%d tcp",
        inet_ntoa(target->sin_addr),
        ntohs(target->sin_port));
  close(sock);
  bank_put(target);
  sem_post(&globals->check_sem);
  return 0;
}


void * nmap_parser_thread(void *arg)
{

  char buff[BUFF_SIZ];
  char buff_target[BUFF_TARGET_SIZ];
  char host[BUFF_HOST_SIZ];
  char port[BUFF_PORT_SIZ];
  regex_t  host_regex,port_regex;
  regmatch_t  match_regex;
  int position;

  regcomp(&host_regex,"Host: [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}",REG_EXTENDED);
  regcomp(&port_regex,"[0-9]{1,5}/open/",REG_EXTENDED);

  for(;;)
  {

    if(0>=read_pipe_line(globals->nmap_output_fd,buff,sizeof(buff)))
      break;

    write_log(4,FFL,"%s",buff);

   if(buff[0]=='#')
    {
        if(strstr(buff,"completed"))
          break;
        else
          continue;
    }

    if(strstr(buff,"QUITTING") || strstr(buff,"Usage")) {
           write_log(1,FFL,"BAD NMAP OPTIONS");
           break;
    }

    if(0==regexec(&host_regex,buff,1,&match_regex,0))
    {
      memset(host,0,sizeof(host));
      strncpy(host, &buff[match_regex.rm_so+6],match_regex.rm_eo-match_regex.rm_so-6);
      position=match_regex.rm_eo+1;
      while(0==regexec(&port_regex,&buff[position],1,&match_regex,0))
      {
            memset(port,0,sizeof(port));
            strncpy(port, &buff[position+match_regex.rm_so],match_regex.rm_eo-match_regex.rm_so-6);
            position+=match_regex.rm_eo+1;
            sprintf(buff_target,"%s %s %d\n",host,port,ALL_TYPES);
            write(globals->target_input_fd,buff_target,strlen(buff_target));
      }//while ports
    }//if host
  }//for
  close(globals->target_input_fd);
  return 0;
}

void * file_parser_thread(void *arg)
{
	char buff[BUFF_SIZ];
 	char target_line[BUFF_TARGET_SIZ];
  	struct hostent *he;
 	char *p;
  	int ntmp;
	while(-1!=read_pipe_line(STDIN_FILENO,buff,sizeof(buff)))
	{
   	  if(globals->et==HUNTER_FILE_E){
    		p=strtok(buff,":");
     		if(!p)continue;
       	he=gethostbyname(&p[strspn(p," ")]);
        	if(!he)continue;
       	memset(target_line,0,sizeof(target_line));
        	sprintf(target_line,"%s",inet_ntoa(*(struct in_addr*)he->h_addr));
        	p=strtok(NULL,"@");
     		if(!p)continue;
       	ntmp=atoi(p);
        	if(ntmp<1&&ntmp>65535)continue;
       	sprintf(&target_line[strlen(target_line)]," %d",ntmp);
		p=strtok(NULL,"\n");
     		if(!p)continue;
       	if(strstr(p,"http") || strstr(p,"HTTP") )
               	sprintf(&target_line[strlen(target_line)]," %d\n",HTTP_TYPE);
              else if(strstr(p,"socks4") || strstr(p,"SOCKS4"))
               	sprintf(&target_line[strlen(target_line)]," %d\n",SOCKS4_TYPE);
              else if(strstr(p,"socks5") || strstr(p,"SOCKS5"))
               	sprintf(&target_line[strlen(target_line)]," %d\n",SOCKS5_TYPE);
              else
               	sprintf(&target_line[strlen(target_line)]," %d\n",ALL_TYPES);
              write_log(4,FFL,"parsed: %s",target_line) ;
              write(globals->target_input_fd,target_line,strlen(target_line));

          }else{
            	int type;
            	p=strtok(&buff[strspn(buff," ")]," ");
     		if(!p)continue;
       	if(strstr(p,"http"))
			type=HTTP_TYPE;
              else if(strstr(p,"socks4"))
               	type=SOCKS4_TYPE;
              else if(strstr(p,"socks5"))
               	type=SOCKS5_TYPE;
              else
               	type=ALL_TYPES;
		p=strtok(NULL," ");
        	if(!p)continue;
       	he=gethostbyname(p);
        	if(!he)continue;
       	memset(target_line,0,sizeof(target_line));
        	sprintf(target_line,"%s",inet_ntoa(*(struct in_addr*)he->h_addr));
        	p=strtok(NULL,"\n");
     		if(!p)continue;
       	ntmp=atoi(p);
        	if(ntmp<1&&ntmp>65535)continue;
       	sprintf(&target_line[strlen(target_line)]," %d",ntmp);
     		sprintf(&target_line[strlen(target_line)]," %d\n",type);
       	write_log(4,FFL,"parsed: %s",target_line) ;
              write(globals->target_input_fd,target_line,strlen(target_line));

          }
	}

  close(globals->target_input_fd);
  return 0;
}


