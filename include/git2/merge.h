/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_git_merge_h__
#define INCLUDE_git_merge_h__

#include "git2/common.h"
#include "git2/types.h"
#include "git2/oid.h"
#include "git2/diff_tree.h"
#include "git2/checkout.h"

/**
 * @file git2/merge.h
 * @brief Git merge routines
 * @defgroup git_merge Git merge routines
 * @ingroup Git
 * @{
 */
GIT_BEGIN_DECL

/**
 * Option flags for `git_merge`.
 *
 * GIT_MERGE_NO_FASTFORWARD - Do not fast-forward.
 */
enum {
	GIT_MERGE_NO_FASTFORWARD      = (1 << 0),
	GIT_MERGE_FASTFORWARD_ONLY    = (1 << 1),
};

/**
 * Resolver options for `git_merge_strategy_resolve`.
 */ 
enum {
	GIT_MERGE_RESOLVE_NO_REMOVED = (1 << 0),
	GIT_MERGE_RESOLVE_NO_AUTOMERGE = (1 << 1),
	GIT_MERGE_RESOLVE_FAVOR_OURS = (1 << 2),
	GIT_MERGE_RESOLVE_FAVOR_THEIRS = (1 << 3),
};

enum {
	GIT_MERGE_CONFLICT_NO_DIFF3 = (1 << 0),
	GIT_MERGE_CONFLICT_NO_SIDES = (1 << 1),
};

#define GIT_MERGE_TREES_OPTS_INIT {0}

typedef struct {
	unsigned int diff_flags;
	unsigned int resolve_flags;
} git_merge_trees_opts;

#define GIT_MERGE_OPTS_INIT {0, GIT_MERGE_TREES_OPTS_INIT, 0, GIT_CHECKOUT_OPTS_INIT}

typedef struct {
	unsigned int merge_flags;
	git_merge_trees_opts merge_trees_opts;
	unsigned int conflict_flags;

	git_checkout_opts checkout_opts;
} git_merge_opts;

/**
 * Determines if a merge is in progress
 *
 * @param out true if there is a merge in progress
 * @param repo the repository where the merge may be in progress
 */
GIT_EXTERN(int) git_merge_inprogress(int *out, git_repository *repo);

/**
 * Find a merge base between two commits
 *
 * @param out the OID of a merge base between 'one' and 'two'
 * @param repo the repository where the commits exist
 * @param one one of the commits
 * @param two the other commit
 */
GIT_EXTERN(int) git_merge_base(git_oid *out, git_repository *repo, const git_oid *one, const git_oid *two);

/**
 * Find a merge base given a list of commits
 *
 * @param out the OID of a merge base considering all the commits
 * @param repo the repository where the commits exist
 * @param input_array oids of the commits
 * @param length The number of commits in the provided `input_array`
 */
GIT_EXTERN(int) git_merge_base_many(git_oid *out, git_repository *repo, const git_oid input_array[], size_t length);

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

GIT_EXTERN(int) git_merge_trees(
	git_merge_result **out,
	git_repository *repo,
	git_index *index,
	const git_tree *ancestor_tree,
	const git_tree *our_tree,
	const git_tree *their_tree,
	const git_merge_trees_opts *opts);

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

/**
 * Free a merge result.
 *
 * @param merge_result the merge result to free
 */
GIT_EXTERN(void) git_merge_result_free(git_merge_result *merge_result);

GIT_EXTERN(int) git_merge_head_from_ref(git_merge_head **out, git_repository *repo, git_reference *ref);
GIT_EXTERN(int) git_merge_head_from_oid(git_merge_head **out, git_repository *repo, const git_oid *oid);
GIT_EXTERN(void) git_merge_head_free(git_merge_head *head);


/** @} */
GIT_END_DECL
#endif
