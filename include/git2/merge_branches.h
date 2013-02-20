/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_git_merge_branches_h__
#define INCLUDE_git_merge_branches_h__

#include "git2/merge.h"
#include "git2/common.h"
#include "git2/types.h"
#include "git2/oid.h"
#include "git2/diff_tree.h"
#include "git2/checkout.h"

/**
 * @file git2/merge_branches.h
 * @brief Git merge branch routines
 * @defgroup git_merge Git merge branch routines
 * @ingroup Git
 * @{
 */
GIT_BEGIN_DECL

/**
 * Option flags for `git_merge`.
 *
 * GIT_MERGE_NO_FASTFORWARD - Do not fast-forward.
 */
typedef enum {
	GIT_MERGE_NO_FASTFORWARD      = 1,
	GIT_MERGE_FASTFORWARD_ONLY    = 2,
} git_merge_flags_t;

enum {
	GIT_MERGE_CONFLICT_NO_DIFF3 = (1 << 0),
	GIT_MERGE_CONFLICT_NO_SIDES = (1 << 1),
};

typedef struct {
	unsigned int version;

	git_merge_flags_t merge_flags;
	git_merge_tree_opts merge_tree_opts;
	unsigned int conflict_flags;
	
	git_checkout_opts checkout_opts;
} git_merge_opts;

#define GIT_MERGE_OPTS_VERSION 1
#define GIT_MERGE_OPTS_INIT {GIT_MERGE_OPTS_VERSION, 0, GIT_MERGE_TREE_OPTS_INIT, 0, GIT_CHECKOUT_OPTS_INIT}

/**
 * Merges the given commits into HEAD, producing a new commit.
 *
 * @param out the results of the merge
 * @param repo the repository to merge
 * @param merge_heads the heads to merge into
 * @param merge_heads_len the number of heads to merge
 * @param flags merge flags
 */
GIT_EXTERN(int) git_merge(
	git_merge_result **out,
	git_repository *repo,
	const git_merge_head **their_heads,
	size_t their_heads_len,
	const git_merge_opts *opts);

/**
 * Returns true if a merge is up-to-date (we were asked to merge the target
 * into itself.)
 */
GIT_EXTERN(int) git_merge_result_is_uptodate(git_merge_result *merge_result);

/**
 * Returns true if a merge is eligible for fastforward
 */
GIT_EXTERN(int) git_merge_result_is_fastforward(git_merge_result *merge_result);

/**
 * Gets the fast-forward OID if the merge was a fastforward.
 *
 * @param out the OID of the fast-forward
 * @param merge_result the results of the merge
 */
GIT_EXTERN(int) git_merge_result_fastforward_oid(git_oid *out, git_merge_result *merge_result);

GIT_EXTERN(int) git_merge_result_delta_foreach(git_merge_result *merge_result,
	git_diff_tree_delta_cb delta_cb,
	void *payload);

GIT_EXTERN(int) git_merge_result_conflict_foreach(git_merge_result *merge_result,
	git_diff_tree_delta_cb conflict_cb,
	void *payload);

GIT_EXTERN(int) git_merge_head_from_ref(git_merge_head **out, git_repository *repo, git_reference *ref);
GIT_EXTERN(int) git_merge_head_from_oid(git_merge_head **out, git_repository *repo, const git_oid *oid);
GIT_EXTERN(void) git_merge_head_free(git_merge_head *head);


/** @} */
GIT_END_DECL
#endif
