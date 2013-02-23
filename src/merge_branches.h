/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_merge_branches_h__
#define INCLUDE_merge_branches_h__

#include "git2/merge_branches.h"

#define MERGE_CONFIG_FILE_MODE		0666

/** Internal structure for merge inputs */
struct git_merge_head {
	char *branch_name;
	git_oid oid;
	
	git_commit *commit;
};

/** Internal structure for merge results */
struct git_merge_result {
	bool is_uptodate;
	
	bool is_fastforward;
	git_oid fastforward_oid;
	
	git_merge_index *diff_tree;
	git_vector conflicts;
};

int git_merge__setup(
	git_repository *repo,
	const git_merge_head *our_head,
	const git_merge_head *their_heads[],
	size_t their_heads_len,
	unsigned int flags);

#endif