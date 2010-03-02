/*
 *	xt_expr - arbitrary expression matcher
 *	Copyright © Jan Engelhardt, 2009-2010
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License; either
 *	version 2 of the License, or any later version, as published by the
 *	Free Software Foundation.
 */
#include <linux/netfilter/x_tables.h>
#include <net/netfilter/nf_conntrack.h>
#include "xt_expr.h"
#include "compat_xtables.h"

/*
 * 1. Immediates
 *
 * An immediate value (or "atom", but we won't use that term) would be
 * something like the integer "21". Because there is no real use in having
 * freestanding (design-wise) atoms -- that is, they would be pretty much in
 * a void context so to speak -- these are tied to an operator (which may be
 * the no-op operator), forming the micro-expression.
 *
 * 2. Micro-expressions
 *
 * A micro-expression (µexpr) is the fundamental unit in xt_expr. It
 * represents a function with two arguments and is encoded as struct
 * xt_expr_micro. In the simplest case, the arguments are immediate values.
 * Standard unary functions/operators such as negation simply ignore their
 * second argument. With that we can already represent "4+2" for example as
 * {XTEXPR_OP_ADD, 4, 2}. In practice, the flags XTEXPR_LHIMM and
 * XTEXPR_RHIMM are OR-ed onto XTEXPR_OP_ADD to denote the use of immediate
 * values as we will shortly see. The first argument is called the left-hand
 * side (LH), the second is the right-hand side (RH).
 *
 * 3. Variables
 *
 * To support external variables instead of just immediate values, a flag is
 * turned that changes the meaning of the LH and/or RH when evaluated. The
 * previous example of "4+2" would have been encoded as
 *
 * 	(struct xt_expr_micro)
 * 	{XTEXPR_OP_ADD | XTEXPR_LHIMM | XTEXPR_RHIMM, 4, 2}
 *
 * Select the particular variable/type and have the IMM flag unset. To yield
 * the packet mark plus one, this struct could be used:
 *
 * 	{XTEXPR_OP_ADD | XTEXPR_LHIMM, 1, XTEXPR_TYPE_NFMARK}
 *
 * 4. Subexpressions
 *
 * Subexpressions offer a way to place parentheses, and to chain exprs.
 * "1+2+3+4" would need to be expressed as (1+2)+(3+4) to fit into the
 * micro-expression layout. To denote that the LH or RH is a subexpression,
 * just use XTEXPR_TYPE_SUB.
 *
 * The serialization of the expression tree into structs happens in preorder
 * fashion, i.e. {parent, left, right}. By having the parent present first on
 * unserialization, a single unidirectionally "walking pointer" can be used,
 * and no temporary registers or an RPM evaluator stack are required.
 * (The magic here is to use recursion and C's "stack".)
 * The evaluation order is always left-to-right.
 *
 * An "expression block" is all the space that a struct and its
 * subexpression take up. By definition it must always be contiguous
 * in memory.
 *
 * The last example would therefore be:
 * 	{XTEXPR_OP_ADD, XTEXPR_TYPE_SUB, XTEXPR_TYPE_SUB}
 * 	{XTEXPR_OP_ADD | XTEXPR_LHIMM | XTEXPR_RHIMM, 1, 2}
 * 	{XTEXPR_OP_ADD | XTEXPR_LHIMM | XTEXPR_RHIMM, 3, 4}
 *
 * 5. n-ary operators
 *
 * Since micro-expressions are limited to two operands, the ?: ternany operator
 * needs to be encoded with an indirect node in the expression tree.
 *
 * 	res = cond ? true : false;
 * =>
 * 	{XTEXPR_OP_IF, cond, XTEXPR_TYPE_SUB}
 * 	{XTEXPR_OP_ELSE, true, false}
 */

static uintxp_t xt_expr_rvalue(const struct sk_buff *skb, unsigned int reg)
{
	const struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;

	switch (reg) {
	case XTEXPR_TYPE_NFMARK:
		return skb->mark;
	case XTEXPR_TYPE_CTMARK:
		ct = nf_ct_get(skb, &ctinfo);
		return (ct != NULL) ? ct->mark : 0;
	case XTEXPR_TYPE_L3PROTO:
		return ntohl(skb->protocol);
	default:
		return 0;
	}
}

/**
 * xtexpr_descend - evaluate µexpr
 * @skb:	current packet being processed
 * @atom:	atom to evalute
 * @retp:	storage location for result of operation
 *
 * Evaluate the given micro-expression. Stores the result in *retp,
 * and returns a pointer to the end of the expression block.
 */
static const struct xt_expr_micro *xt_expr_descend(const struct sk_buff *skb,
    const struct xt_expr_micro *mx, uintxp_t *retp)
{
	const struct xt_expr_micro *next = mx + 1;
	uintxp_t lh, rh, ret;

	if (mx->op & XTEXPR_LHIMM)
		lh = mx->lh;
	else if (mx->lh == XTEXPR_TYPE_SUB)
		next = xt_expr_descend(skb, next, &lh);
	else
		lh = xt_expr_rvalue(skb, mx->rh);

	if (mx->op & XTEXPR_RHIMM)
		rh = mx->rh;
	else if (mx->rh == XTEXPR_TYPE_SUB)
		next = xt_expr_descend(skb, next, &rh);
	else
		rh = xt_expr_rvalue(skb, mx->rh);

	switch (mx->op & XTEXPR_OPMASK) {
	case XTEXPR_OP_NONE: ret = lh; break;
	case XTEXPR_OP_ADD: ret = lh + rh; break;
	case XTEXPR_OP_SUB: ret = lh - rh; break;
	case XTEXPR_OP_MUL: ret = lh * rh; break;
	case XTEXPR_OP_DIV: ret = lh / rh; break;
	case XTEXPR_OP_MOD: ret = lh % rh; break;
	case XTEXPR_OP_NEG: ret = -lh; break;
	case XTEXPR_OP_LT:  ret = lh < rh; break;
	case XTEXPR_OP_LE:  ret = lh <= rh; break;
	case XTEXPR_OP_EQ:  ret = lh == rh; break;
	case XTEXPR_OP_NE:  ret = lh != rh; break;
	case XTEXPR_OP_GT:  ret = lh > rh; break;
	case XTEXPR_OP_GE:  ret = lh >= rh; break;
	case XTEXPR_OP_LNOT: ret = !lh; break;
	case XTEXPR_OP_LAND: ret = lh && rh; break;
	case XTEXPR_OP_LOR:  ret = lh || rh; break;
	case XTEXPR_OP_SHL:  ret = lh << rh; break;
	case XTEXPR_OP_SHR:  ret = lh >> rh; break;
	case XTEXPR_OP_NOT:  ret = ~lh; break;
	case XTEXPR_OP_AND:  ret = lh & rh; break;
	case XTEXPR_OP_OR:   ret = lh | rh; break;
	case XTEXPR_OP_XOR:  ret = lh ^ rh; break;
	default: ret = 0; break;
	}
	*retp = ret;
	return next;
}

static bool xt_expr_mt(const struct sk_buff *skb, struct xt_action_param *par)
{
	uintxp_t ret;

	xt_expr_descend(skb, par->matchinfo, &ret);
	return ret;
}

static int xt_expr_mtcheck(const struct xt_mtchk_param *par)
{
	struct xt_expr_mtinfo *xi = par->matchinfo;
	size_t z = sizeof(*xi->blk) * xi->items;
	struct xt_expr_micro *blk;

	blk = vmalloc(z);
	if (blk == NULL)
		return -ENOMEM;
	if (copy_from_user(blk, xi->blk, z) != 0) {
		vfree(blk);
		return -EFAULT;
	}
	xi->blk = blk;
	return 0;
}

static void xt_expr_mtdestroy(const struct xt_mtdtor_param *par)
{
	const struct xt_expr_mtinfo *xi = par->matchinfo;

	vfree(xi->blk);
}

static struct xt_match xt_expr_mtreg __read_mostly = {
	.name       = "expr",
	.revision   = 0,
	.family     = NFPROTO_UNSPEC,
	.checkentry = xt_expr_mtcheck,
	.destroy    = xt_expr_mtdestroy,
	.match      = xt_expr_mt,
	.matchsize  = sizeof(struct xt_expr_mtinfo),
	.me         = THIS_MODULE,
};

static int __init xt_expr_mtinit(void)
{
	return xt_register_match(&xt_expr_mtreg);
}

static void __exit xt_expr_mtexit(void)
{
	xt_unregister_match(&xt_expr_mtreg);
}

MODULE_DESCRIPTION("Xtables: Arbitrary expression match");
MODULE_AUTHOR("Jan Engelhardt <jengelh@medozas.de>");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_expr");
MODULE_ALIAS("ip6t_expr");
MODULE_ALIAS("arpt_expr");
MODULE_ALIAS("ebt_expr");
module_init(xt_expr_mtinit);
module_exit(xt_expr_mtexit);
