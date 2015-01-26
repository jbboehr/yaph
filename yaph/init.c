/***************************************************************************
 init.c  -  initialize scanner
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
void usage() {
	printf("\nYAPH - Yet Another Proxy Hunter version %s  %s", YAPH_VERSION,
			"\nFind & Validate socks v4, socks v5 and http(ssl-connect) proxy servers."
					"\nResults are stored in ./found_proxies.log by default"
					"\n\nUsage: yaph <engine> [parameters]"
					"\n <engine> is one of following options:"
					"\n\t --use_nmap \t utilizes Nmap (the great scanner by fyodor, "
					"\n\t\t\t many thanks) to found targets. (you have to be root)"
					"\n\t\t\t nmap have to be installed to use this option."
					"\n\t --use_hunter_stdin \t reads targets form stdin. "
					"\n\t\t\t\t proxyhunter syntax. host:port@type"
					"\n\t\t\t\t separated by new line."
					"\n\t --use_chains_stdin \t reads targets from stdin."
					"\n\t\t\t\t proxychains syntax. type host port"
					"\n\t\t\t\t separated by new line."
					"\n [parameters] are used only for nmap engine"
					"\n\t It can be any nmap command line parameter."
					"\n\t read 'man nmap' for more details."
					"\n\t The must parameter is target host or net."
					"\n\t The default parameters passed by YAPH to Nmap are:"
					"\n\t -n -oG - -randomize_hosts -sS -p 1080,8080,3128 -PT4665"
					"\n\t it means -> hosts are pinged with TCP ACK packet to port 4665,"
					"\n\t ports 1080,8080,3128 of 'live' hosts are scanned using"
					"\n\t TCP SYN packet and 'open' ports are cheked by yaph."
					"\n\t You can provide your own nmap parameters except output-type '-oG'"
					"\n\nCommon usage examples:"
					"\n cat proxy_list.txt | sort | uniq | yaph --use_hunter_stdin"
					"\n\t This will check proxy addresses stored in file 'proxy_list.txt'"
					"\n\t  in format host:port@type separated by newline"
					"\n\t  sort & uniq is useful when your list contains not unique targets"
					"\n cat proxy_list.txt | sort | uniq | proxychains yaph --use_hunter_stdin"
					"\n\t The same like above but check via proxy. ProxyChains must be installed"
					"\n\t to use this feature."
					"\n proxychains yaph --use_nmap -sT -P0 192.168.0.0/16"
					"\n\t Stealth proxy mode. your IP is undetectable by IDS. "
					"\n\t Hosts are not pinged. tcp connect() scan"
					"\n\t is performed via proxy and open ports are checked via proxy also."
					"\n\t Proxy server that used to hide your IP adress"
					"\n\t is defined by configuration of ProxyChains"
					"\n yaph --use_nmap -D192.168.1.1,192.168.1.2,192.168.1.3 192.168.0.0/16"
					"\n\t Stelath decoy mode. You can put as many decoys as you wish (man nmap)"
					"\n\t it is hard to identify your IP wile using decoys"
					"\n\t only if the decoys are real hosts (and they are up) ."
					"\n\t Decoyes are used to ping and scan target hosts."
					"\n yaph --use_nmap -iR"
					"\n\t Scan random hosts on internet trying to find proxy"
					"\n\t on ports 1080 8080 3128. Hosts are pinged with TCP ACK packet"
					"\n\t to port 4665, ports of 'live' hosts are scanned"
					"\n\t using TCP SYN packet and 'open' ports are cheked by yaph. "
					"\n yaph 192.168.10.*"
					"\n\t short syntax. does the same as:"
					"\n\t yaph --use_nmap -sS -pT4665 -p 1080,8080,3128 192.168.10.*"
					"\nDependencies: \n\tnmap ver 3 and above, proxychains ver 1.8 and above."
					"\n\n Read more help in README file\n");
	exit(EXIT_SUCCESS);
}
void check_nmap_state() {
	/*
	 *  check user id for nmap engine
	 */
	if( getuid() && !globals->privileged ) {
		printf(
				"You should be root to run yaph with nmap engine, or use setcap and pass --privileged\n");
		exit(EXIT_SUCCESS);
	}
//fstat
}

void init_options(int argc, char *argv[]) {

	char result_file[1024], log_file[1024];
	char port_list = 0, ping_type = 0, scan_type = 0, default_engine = 0;
	struct hostent * he;
	umask(022);
	globals = malloc(sizeof(global_data));
	if (!globals)
		exit_error(errno);
	memset(globals, 0, sizeof(global_data));

	globals->content_host = malloc(1024 * 8);
	if (!globals->content_host)
		exit_error(errno);
	globals->content_data = malloc(1024 * 8);
	if (!globals->content_data)
		exit_error(errno);
	globals->content_request = malloc(1024 * 8);
	if (!globals->content_request)
		exit_error(errno);
// ----  defaults
	he = gethostbyname(CONTENT_HOST);
	if (!he)
		exit_error(errno);
	sprintf(globals->content_host, "%s", inet_ntoa(*(struct in_addr*) he->h_addr));
	strcpy(result_file, "./found_proxies.log");
	strcpy(log_file, "./yaph.log");
	globals->content_port = CONTENT_PORT;
	globals->debug_level = 100;
	globals->et = -1;
	globals->tcp_read_time_out = 15 * 1000; // milliseconds
	globals->tcp_connect_time_out = 15 * 1000; // milliseconds
	globals->paral_checks = 20;
	strcpy(globals->content_data, CONTENT_DATA);
	strcpy(globals->content_request, CONTENT_REQUEST);

	{ /// config file routine
		FILE *cnf = NULL;
		char buff[1024];
		if (!(cnf = fopen("./yaph.conf", "rb")))
			if (!(cnf = fopen("/etc/yaph.conf", "rb")))
				goto no_file;
		while (fgets(buff, sizeof(buff), cnf)) {
			if (buff[strspn(buff, " ")] != '#') {
				if (strstr(buff, "MaxCheckThreads")) {
					char *c = strchr(buff, '=');
					int x = atoi(c ? c + 1 : "-1");
					if (x > 0)
						globals->paral_checks = x;
				} else if (strstr(buff, "TcpReadTimeOut")) {
					char *c = strchr(buff, '=');
					int x = atoi(c ? c + 1 : "-1");
					if (x > 0)
						globals->tcp_read_time_out = x;
				} else if (strstr(buff, "TcpConnectTimeOut")) {
					char *c = strchr(buff, '=');
					int x = atoi(c ? c + 1 : "-1");
					if (x > 0)
						globals->tcp_connect_time_out = x;
				} else if (strstr(buff, "ContentHost")) {
					char *c = strchr(buff, '=');
					char tmp[1024];
					if (!c)
						continue;
					bzero(tmp, sizeof(tmp));
					sscanf(++c, "%s", tmp);
					if (!tmp[0])
						continue;
					he = gethostbyname(tmp);
					if (!he)
						continue;
					sprintf(globals->content_host, "%s",
							inet_ntoa(*(struct in_addr*) he->h_addr));
				} else if(strstr(buff,"ContentPort")) {
					char *c=strchr(buff,'=');
					int x=atoi(c?c+1:"-1");
					if(x>0)globals->content_port=x;
				} else if(strstr(buff,"ContentRequest")) {
					char *c=strchr(buff,'=');
					char *p1=NULL,*p2=NULL;
					char tmp[1024];
					if(!c) continue;
					p1=strchr(c,'"');
					p2=strrchr(c,'"');
					if(!(p1&&p2&&p1!=p2)) continue;
					strncpy(tmp,p1+1,p2-p1-1);
					c2bin(tmp,globals->content_request);
				} else if(strstr(buff,"ContentData")) {
					char *c=strchr(buff,'=');
					char tmp[1024];
					if(!c) continue;
					bzero(tmp,sizeof(tmp));
					sscanf(++c,"%s",tmp);
					if(!tmp[0]) continue;
					strcpy(globals->content_data,tmp);
				} else if(strstr(buff,"ResultFile")) {
					char *c=strchr(buff,'=');
					char tmp[1024];
					if(!c) continue;
					bzero(tmp,sizeof(tmp));
					sscanf(++c,"%s",tmp);
					if(!tmp[0]) continue;
					strcpy(result_file,tmp);
				} else if(strstr(buff,"LogFile")) {
					char *c=strchr(buff,'=');
					char tmp[1024];
					if(!c) continue;
					bzero(tmp,sizeof(tmp));
					sscanf(++c,"%s",tmp);
					if(!tmp[0]) continue;
					strcpy(log_file,tmp);
				} else if(strstr(buff,"LogLevel")) {
					char *c=strchr(buff,'=');
					int x=atoi(c?c+1:"-1");
					if(x>0)globals->debug_level=x;
				}
			}
		}
		no_file: ;
	}

// ------   open files
	if (strcmp(result_file, "STDOUT")) {
		if (0 >= (globals->result_f = fopen(result_file, "a+")))
			exit_error(errno);
	} else
		globals->result_f = stdout;

	if (strcmp(log_file, "STDOUT")) {
		if (!(globals->log_file_f = fopen(log_file, "a+")))
			exit_error(errno);
	} else
		globals->log_file_f = stdout;

	{ // process command line options nere
		int option_index = 0;
		char c;
		struct option long_options[] = {
				{ "use_hunter_stdin", 0, (int*) &globals->et, HUNTER_FILE_E },
				{ "use_chains_stdin", 0, (int*) &globals->et, OUR_FILE_E },
				{ "use_nmap", 0, (int*) &globals->et, NMAP_E },
				{ "privileged", 0, (int*) &globals->privileged, 1 },
				{ 0, 0, 0, 0 }
		};
		if (argc < 2)
			usage();
		opterr = 0;
		while (-1
				!= (c = getopt_long_only(argc, argv, "p:s:P:o::h", long_options,
						&option_index))) {
			switch (c) {
			case 0:
				break;
			case '?':
				break;
			case 'p':
				port_list = 1;
				break;
			case 's':
				scan_type = 1;
				break;
			case 'P':
				ping_type = 1;
				break;

			default:
				usage();
			}
		}

	}       /// command line processing
	if (globals->et == -1) {
		globals->et = NMAP_E;
		default_engine = 1;
	}

	if (globals->et == NMAP_E) {
		int my_argc, max_my_argc, kam;

		check_nmap_state();
		max_my_argc = 9;
		my_argc = max_my_argc;

		globals->nmap_string = malloc((argc + max_my_argc) * sizeof(char*));
		if (!globals->nmap_string)
			exit_error(errno);
		memset(globals->nmap_string, 0, (argc + max_my_argc) * sizeof(char*));

		globals->nmap_string[0] = malloc(5);
		if (!globals->nmap_string[0])
			exit_error(errno);
		strcpy(globals->nmap_string[0], "nmap");

		globals->nmap_string[1] = malloc(3);
		if (!globals->nmap_string[1])
			exit_error(errno);
		strcpy(globals->nmap_string[1], "-n");

		globals->nmap_string[2] = malloc(4);
		if (!globals->nmap_string[2])
			exit_error(errno);
		strcpy(globals->nmap_string[2], "-oG");

		globals->nmap_string[3] = malloc(2);
		if (!globals->nmap_string[3])
			exit_error(errno);
		strcpy(globals->nmap_string[3], "-");

		globals->nmap_string[4] = malloc(17);
		if (!globals->nmap_string[4])
			exit_error(errno);
		strcpy(globals->nmap_string[4], "-randomize_hosts");

		kam = 4;
		if (!port_list) {
			globals->nmap_string[++kam] = malloc(3);
			if (!globals->nmap_string[kam])
				exit_error(errno);
			strcpy(globals->nmap_string[kam], "-p");
			globals->nmap_string[++kam] = malloc(15);
			if (!globals->nmap_string[kam])
				exit_error(errno);
			strcpy(globals->nmap_string[kam], "1080,8080,3128");
		} else
			my_argc -= 2;

		if (!ping_type) {
			globals->nmap_string[++kam] = malloc(8);
			if (!globals->nmap_string[kam])
				exit_error(errno);
			strcpy(globals->nmap_string[kam], "-PT4665");
		} else
			my_argc -= 1;

		if (!scan_type) {
			globals->nmap_string[++kam] = malloc(4);
			if (!globals->nmap_string[kam])
				exit_error(errno);
			strcpy(globals->nmap_string[kam], "-sS");
		} else
			my_argc -= 1;

		{
			int i, start_position = (default_engine ? 1 : 2);
			for (i = start_position; i < argc; i++)
				globals->nmap_string[i + my_argc - start_position] = argv[i];
		}
	}

	pthread_mutex_init(&(globals->mutex), NULL);
	if (-1 == sem_init(&globals->check_sem, 0, globals->paral_checks))
		exit_error(errno);

	bank_init();
	init_engine();

}

void init_engine() {
	int filedes[2];
	int pid;
	pthread_t pid_t;

	if (0 > pipe(filedes))
		exit_error(errno);
	globals->target_input_fd = filedes[1];
	globals->target_output_fd = filedes[0];

	switch (globals->et) {
	case NMAP_E:
		if (0 > pipe(filedes))
			exit_error(errno)
		;
		globals->nmap_input_fd = filedes[1];
		globals->nmap_output_fd = filedes[0];

		if ((pid = fork())) {
			globals->nmap_pid = pid;
			if (0 > pthread_create(&pid_t, NULL, nmap_parser_thread, NULL))
				exit_error(errno);
		} else {
			close(STDIN_FILENO);
			dup2(globals->nmap_input_fd, STDERR_FILENO);
			dup2(globals->nmap_input_fd, STDOUT_FILENO);
			execvp("nmap", globals->nmap_string);
			exit_error(errno);
		}
		break;
	case HUNTER_FILE_E:
	case OUR_FILE_E:
		if (0 > pthread_create(&pid_t, NULL, file_parser_thread, NULL))
			exit_error(errno)
		;
	}       //switch
}
