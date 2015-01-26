/***************************************************************************
                          main.c  -  main function
                             -------------------
    begin                : Sat Dec 28 21:13:43 IST 2002
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

global_data * globals=NULL;

void init_check(void * (*func)(void *),struct sockaddr_in *addr)
{
     struct sockaddr_in *arg=NULL;
     pthread_t  thread_id;
     int sem_val;

              sem_wait(&globals->check_sem);
              sem_getvalue(&globals->check_sem,&sem_val);
              write_log(1,FFL,"Targets in progress = %d .. ", ( globals->paral_checks - sem_val));
              arg=bank_get();
              memcpy(arg,addr,sizeof(struct sockaddr_in));
              while(EAGAIN==pthread_create(&thread_id, NULL, func, (void*)arg))
              {
                   sem_wait(&globals->check_sem);
                   globals->paral_checks--;
                   if(globals->paral_checks<=0)
                                       exit_error(errno);
                   write_log(4,FFL,"Decremented MaxCheckThreads to %d", globals->paral_checks);
                 //  usleep(1);
              }

}


int main(int argc, char *argv[])
{

  target_st  target;
  int sem_val;

  init_options(argc, argv);

  write_log(1,FFL,"START");
  for(;;)
  {
       if(-1==get_target(&target))
          break;

       switch(target.type)
       {
         case HTTP_TYPE:	
              init_check(check_http,&target.target_addr);
              break;	

         case SOCKS4_TYPE:
              init_check(check_socks4,&target.target_addr);
             	break;	

          case SOCKS5_TYPE:	
         	init_check(check_socks5,&target.target_addr);
             	break;	

           case ALL_TYPES:	
          	init_check(check_http,&target.target_addr);
              init_check(check_socks4,&target.target_addr);
              init_check(check_socks5,&target.target_addr);
             	break;	
       }
  }


  do //  just wait for the rest of threads
  {
         sleep(5);
         sem_getvalue(&globals->check_sem,&sem_val);
         write_log(1,FFL,"Targets in progress = %d .. ",(globals->paral_checks - sem_val));
  } while(sem_val!=globals->paral_checks) ;

  write_log(1,FFL,"DONE");
  return EXIT_SUCCESS;
}
