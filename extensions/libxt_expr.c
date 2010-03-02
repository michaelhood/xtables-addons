/*
 *	xt_expr - arbitrary expression matcher
 *	Copyright © Jan Engelhardt, 2009-2010
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License; either
 *	version 2 of the License, or any later version, as published by the
 *	Free Software Foundation.
 */
#include <getopt.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <xtables.h>
#include "xt_expr.h"

static const struct option expr_mt_opts[] = {
	{.name = "expr", .has_arg = true, .val = 'e'},
	{NULL},
};

static void expr_mt_help(void)
{
	printf(
"expr match options:\n"
"  --expr EXPR           Umm, expression?\n"
);
}

static struct xt_expr_micro *expr_parse(const char *s, unsigned int *items)
{
	//...
	return NULL;
}

static int expr_mt_parse(int c, char **argv, int invert, unsigned int *flags,
			 const void *entry, struct xt_entry_match **match)
{
	struct xt_expr_mtinfo *xi = (void *)(*match)->data;

	switch (c) {
	case 'e':
		xi->blk = expr_parse(optarg, &xi->items);
		return true;
	}
	return false;
}

static void expr_mt_show(const struct xt_expr_micro *blk, unsigned int items)
{
	//hmm, blk is not valid.
}

static void expr_mt_print(const void *ip, const struct xt_entry_match *match,
			  int numeric)
{
	const struct xt_expr_mtinfo *xi = (const void *)match->data;

	printf("expr '");
	expr_mt_show(xi->blk, xi->items);
	printf("' ");
}

static void expr_mt_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_expr_mtinfo *xi = (const void *)match->data;

	printf("--expr '");
	expr_mt_show(xi->blk, xi->items);
	printf("' ");
}

static struct xtables_match expr_mt_reg = {
	.version       = XTABLES_VERSION,
	.name          = "expr",
	.revision      = 0,
	.family        = AF_UNSPEC,
	.size          = XT_ALIGN(sizeof(struct xt_expr_mtinfo)),
	.userspacesize = XT_ALIGN(sizeof(struct xt_expr_mtinfo)), // ?
	.help          = expr_mt_help,
	.parse         = expr_mt_parse,
	.print         = expr_mt_print,
	.save          = expr_mt_save,
	.extra_opts    = expr_mt_opts,
};

static __attribute__((constructor)) void expr_mt_ldr(void)
{
	xtables_register_match(&expr_mt_reg);
}
