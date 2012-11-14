/*
 * Copyright (C) 2009-2012 the libgit2 contributors
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_merge_h__
#define INCLUDE_merge_h__

#include "git2/types.h"

#define GIT_MERGE_MSG_FILE		"MERGE_MSG"
#define GIT_MERGE_MODE_FILE		"MERGE_MODE"

#define MERGE_CONFIG_FILE_MODE	0666

/** Internal structure for merge inputs */
struct git_merge_head {
	char *branch_name;
	git_oid oid;

	git_commit *commit;
};

/** Internal structure for merge results */
struct git_merge_result {

	bool is_fastforward;
	git_oid fastforward_oid;
};

int git_merge__cleanup(git_repository *repo);

#endif
