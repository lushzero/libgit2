/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_merge_h__
#define INCLUDE_merge_h__

#include "vector.h"
#include "commit_list.h"
#include "pool.h"

#include "git2/merge.h"
#include "git2/types.h"

#define GIT_MERGE_MSG_FILE		"MERGE_MSG"
#define GIT_MERGE_MODE_FILE		"MERGE_MODE"

#define GIT_MERGE_TREE_RENAME_THRESHOLD	50
#define GIT_MERGE_TREE_TARGET_LIMIT		1000

struct git_merge_index {
    git_repository *repo;
    git_pool pool;
	
    /* Vector of git_index_entry */
    git_vector staged;
	
    /* Vector of git_merge_index_conflict */
    git_vector conflicts;
	
    /* Vector of git_merge_index_conflict */
    git_vector resolved;
};

/**
 * Description of changes to one file across three trees.
 */
typedef struct {
    git_merge_conflict_type_t type;
	
    git_index_entry ancestor_entry;
	
    git_index_entry our_entry;
    git_delta_t our_status;
	
    git_index_entry their_entry;
    git_delta_t their_status;
} git_merge_index_conflict;

int git_merge__bases_many(
	git_commit_list **out,
	git_revwalk *walk,
	git_commit_list_node *one,
	git_vector *twos);

git_merge_index *git_merge_index__alloc(git_repository *repo);

int git_merge_index__find_differences(
	git_merge_index *merge_index,
	const git_tree *ancestor_tree,
	const git_tree *our_tree,
	const git_tree *their_tree);

int git_merge_index__find_renames(
	git_merge_index *merge_index,
	const git_merge_tree_opts *opts);

#endif
