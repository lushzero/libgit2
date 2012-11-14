/*
 * Copyright (C) 2009-2012 the libgit2 contributors
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_git_merge_h__
#define INCLUDE_git_merge_h__

#include "common.h"
#include "types.h"
#include "oid.h"

/**
 * @file git2/merge.h
 * @brief Git merge-base routines
 * @defgroup git_revwalk Git merge-base routines
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
};

/**
 * Resolver options for `git_merge_strategy_resolve`.
 */ 
enum {
    GIT_MERGE_STRATEGY_RESOLVE_NONE = 0,
	GIT_MERGE_STRATEGY_RESOLVE_OURS = 1,
	GIT_MERGE_STRATEGY_RESOLVE_THEIRS = 2,
};

/* Flags for `git_merge_strategy_resolve`. */
enum {
    GIT_MERGE_STRATEGY_RESOLVE_NO_AUTOMERGE =  (1 << 0),
    GIT_MERGE_STRATEGY_RESOLVE_NO_DIFF3_FILE = (1 << 1),
    GIT_MERGE_STRATEGY_RESOLVE_NO_SIMPLE = (1 << 2),
};

typedef struct git_merge_strategy_resolve_options {
	int resolver;
	int flags;
} git_merge_strategy_resolve_options;

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

typedef int (*git_merge_strategy)(int *success,
	git_repository *repo,
	const git_merge_head *ancestor_head,
	const git_merge_head *our_head,
	const git_merge_head *their_heads[],
	size_t their_heads_len,
	void *data);

/**
 * Merges the given commits into HEAD, producing a new commit.
 *
 * @param out the results of the merge
 * @param repo the repository to merge
 * @param merge_heads the heads to merge into
 * @param merge_heads_len the number of heads to merge
 * @param flags merge flags
 */
GIT_EXTERN(int) git_merge(git_merge_result **out,
	git_repository *repo,
	const git_merge_head *their_heads[],
	size_t their_heads_len,
	unsigned int flags,
	git_merge_strategy strategy,
	void *strategy_data);

GIT_EXTERN(int) git_merge_strategy_resolve(
	int *out,
	git_repository *repo,
	const git_merge_head *ancestor_head,
	const git_merge_head *our_head,
	const git_merge_head *their_heads[],
	size_t their_heads_len,
	void *data);

GIT_EXTERN(int) git_merge_strategy_octopus(
	int *out,
	git_repository *repo,
	const git_merge_head *ancestor_head,
	const git_merge_head *our_head,
	const git_merge_head *their_heads[],
	size_t their_heads_len,
	void *data);

/**
 * Aborts an in-progress merge, resetting to ORIG_HEAD.
 *
 * @param repo the repository to abort
 */
GIT_EXTERN(int) git_merge_abort(git_repository *repo);

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
