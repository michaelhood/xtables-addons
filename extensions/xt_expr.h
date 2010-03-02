#ifndef _LINUX_NETFILTER_XT_EXPR_H
#define _LINUX_NETFILTER_XT_EXPR_H 1

/* TODO: What's better? */
#ifdef BIG_BALLS
#	define uintxp_t uint64_t
#	define __uxp_t __u64
#else
#	define uintxp_t uint32_t
#	define __uxp_t __u32
#endif

enum {
	XTEXPR_OP_NONE = 0,
	XTEXPR_OP_ADD,
	XTEXPR_OP_SUB,
	XTEXPR_OP_MUL,
	XTEXPR_OP_DIV,
	XTEXPR_OP_MOD,
	XTEXPR_OP_NEG,

	/*
	 * Providing about everything here, since encoding !(a==b) for a!=b
	 * would be really costly in space.
	 */
	XTEXPR_OP_LT, /* 7 */
	XTEXPR_OP_LE,
	XTEXPR_OP_EQ,
	XTEXPR_OP_NE,
	XTEXPR_OP_GT,
	XTEXPR_OP_GE,

	XTEXPR_OP_LNOT, /* 13 */
	XTEXPR_OP_LAND,
	XTEXPR_OP_LOR,
	/* XTEXPR_OP_LXOR == XTEXPR_OP_NE */

	XTEXPR_OP_SHL, /* 16 */
	XTEXPR_OP_SHR,
	XTEXPR_OP_NOT,
	XTEXPR_OP_AND,
	XTEXPR_OP_OR,
	XTEXPR_OP_XOR,

	XTEXPR_OP_ASG, /* 22 */
	XTEXPR_OP_OFS,
	XTEXPR_OP_DEREF,
	XTEXPR_OP_IF,
	XTEXPR_OP_CASE, /* 26 */

	XTEXPR_OPMASK = 0xFF,

	XTEXPR_LHIMM = 1 << 6, /* LH is an immediate */
	XTEXPR_RHIMM = 1 << 7, /* RH is an immediate */
};

/* call them registers instead? well I dunno... */
enum {
	XTEXPR_TYPE_NONE = 0,
	XTEXPR_TYPE_SUB,           /* descend */
	XTEXPR_TYPE_THIS,          /* a turing-style "current" pointer */
	XTEXPR_TYPE_NFMARK,        /* packet mark */
	XTEXPR_TYPE_CTMARK,        /* connection mark */
	XTEXPR_TYPE_SECMARK,
	XTEXPR_TYPE_L2PROTO,
	XTEXPR_TYPE_L3PROTO,
	XTEXPR_TYPE_L4PROTO,       /* iptables's -p argument */
	XTEXPR_TYPE_L4OFFSET,      /* layer-4 offset (depends on L4PROTO) */
};

/**
 * struct xt_expr_micro - "micro-expression"
 * @op:	one of the above opcodes; may be ORed with flags
 * @lh:	left-hand side item
 * @rh:	right-hand side item
 */
struct xt_expr_micro {
	__u8 op;
	__uxp_t lh, rh;
};

/**
 * struct xt_expr - (large) expression
 * @items:	number of µexprs in the memory block pointed to by @blk
 * @blk:	expression stream
 */
struct xt_expr_mtinfo {
	__u32 items;
	struct xt_expr_micro *blk __attribute__((aligned(8)));
};

#endif /* _LINUX_NETFILTER_XT_EXPR_H */
