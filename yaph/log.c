/***************************************************************************
                          Log.c  -  utilities
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

#define LOG_BUFF 1024*20

int write_log(int level,char* file, char* func, int line,char *str,...)
{
    char buff[LOG_BUFF];
    char d_stamp[100];
    struct tm tm;
    time_t t;
    va_list arglist;
    FILE * log_file;
    log_file=globals->log_file_f;
    if (level<=globals->debug_level)
    {
        va_start(arglist,str);
        vsprintf(buff,str,arglist);
        va_end(arglist);
        t=time(NULL);
        localtime_r(&t,&tm);
        strftime(d_stamp,99,"%a %d/%b %H:%M:%S",&tm);
        fprintf(log_file,"[%s]:PID=%d:%s:%s:%d:  %s\n",d_stamp,getpid(),file,func,line,buff);
        fflush(log_file);
	}

	return EXIT_SUCCESS;
}

