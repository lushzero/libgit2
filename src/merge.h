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

/** Types of changes when files are merged from branch to branch. */
typedef enum {
	/* No conflict - a change only occurs in one branch. */
	GIT_MERGE_DIFF_NONE = 0,
	
	/* Occurs when a file is modified in both branches. */
	GIT_MERGE_DIFF_BOTH_MODIFIED = (1 << 0),
	
	/* Occurs when a file is added in both branches. */
	GIT_MERGE_DIFF_BOTH_ADDED = (1 << 1),
	
	/* Occurs when a file is deleted in both branches. */
	GIT_MERGE_DIFF_BOTH_DELETED = (1 << 2),
	
	/* Occurs when a file is modified in one branch and deleted in the other. */
	GIT_MERGE_DIFF_MODIFIED_DELETED = (1 << 3),
	
	/* Occurs when a file is renamed in one branch and modified in the other. */
	GIT_MERGE_DIFF_RENAMED_MODIFIED = (1 << 4),
	
	/* Occurs when a file is renamed in one branch and deleted in the other. */
	GIT_MERGE_DIFF_RENAMED_DELETED = (1 << 5),
	
	/* Occurs when a file is renamed in one branch and a file with the same
	 * name is added in the other.  Eg, A->B and new file B.  Core git calls
	 * this a "rename/delete". */
	GIT_MERGE_DIFF_RENAMED_ADDED = (1 << 6),
	
	/* Occurs when both a file is renamed to the same name in the ours and
	 * theirs branches.  Eg, A->B and A->B in both.  Automergeable. */
	GIT_MERGE_DIFF_BOTH_RENAMED = (1 << 7),
	
	/* Occurs when a file is renamed to different names in the ours and theirs
	 * branches.  Eg, A->B and A->C. */
	GIT_MERGE_DIFF_BOTH_RENAMED_1_TO_2 = (1 << 8),
	
	/* Occurs when two files are renamed to the same name in the ours and
	 * theirs branches.  Eg, A->C and B->C. */
	GIT_MERGE_DIFF_BOTH_RENAMED_2_TO_1 = (1 << 9),
	
	/* Occurs when an item at a path in one branch is a directory, and an
	 * item at the same path in a different branch is a file. */
	GIT_MERGE_DIFF_DIRECTORY_FILE = (1 << 10),
	
	/* The child of a folder that is in a directory/file conflict. */
	GIT_MERGE_DIFF_DF_CHILD = (1 << 11),
} git_merge_diff_type_t;


typedef struct {
    git_repository *repo;
    git_pool pool;
	
    /* Vector of git_index_entry */
    git_vector staged;
	
    /* Vector of git_merge_index_conflict */
    git_vector conflicts;
	
    /* Vector of git_merge_index_conflict */
    git_vector resolved;
} git_merge_diff_list;

/**
 * Description of changes to one file across three trees.
 */
typedef struct {
    git_merge_diff_type_t type;
	
    git_index_entry ancestor_entry;
	
    git_index_entry our_entry;
    git_delta_t our_status;
	
    git_index_entry their_entry;
    git_delta_t their_status;
} git_merge_diff;

int git_merge__bases_many(
	git_commit_list **out,
	git_revwalk *walk,
	git_commit_list_node *one,
	git_vector *twos);

void git_merge_diff_list_free(git_merge_diff_list *diff_list);

#endif
