/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "common.h"
#include "repository.h"
#include "filediff.h"

#include "git2/repository.h"
#include "git2/object.h"
#include "git2/index.h"
#include "git2/diff_tree.h"

#include "xdiff/xdiff.h"

#define GIT_FILEDIFF_FILE_EXISTS(X)		((X)->mode != 0)

GIT_INLINE(const char *) filediff_best_path(
	const git_filediff_input *ancestor,
	const git_filediff_input *ours,
	const git_filediff_input *theirs)
{
	if (!GIT_FILEDIFF_FILE_EXISTS(ancestor)) {
		if (strcmp(ours->path, theirs->path) == 0)
			return ours->path;

		return NULL;
	}
	
	if (strcmp(ancestor->path, ours->path) == 0)
		return theirs->path;
	else if(strcmp(ancestor->path, theirs->path) == 0)
		return ours->path;
	
	return NULL;
}

GIT_INLINE(int) filediff_best_mode(
	const git_filediff_input *ancestor,
	const git_filediff_input *ours,
	const git_filediff_input *theirs)
{
	/*
	 * If ancestor didn't exist and either ours or theirs is executable,
	 * assume executable.  Otherwise, if any mode changed from the ancestor,
	 * use that one.
	 */
	if (GIT_FILEDIFF_FILE_EXISTS(ancestor)) {
		if (ours->mode == GIT_FILEMODE_BLOB_EXECUTABLE ||
			theirs->mode == GIT_FILEMODE_BLOB_EXECUTABLE)
			return GIT_FILEMODE_BLOB_EXECUTABLE;
		
		return GIT_FILEMODE_BLOB;
	}
	
	if (ancestor->mode == ours->mode)
		return theirs->mode;
	else if(ancestor->mode == theirs->mode)
		return ours->mode;
	
	return 0;
}

int git_filediff(
	git_filediff_result *out,
	git_filediff_input *ancestor,
	git_filediff_input *ours,
	git_filediff_input *theirs,
	git_filediff_flags flags)
{
	xmparam_t xmparam;
	mmbuffer_t mmbuffer;
	int xdl_result;
	int error = 0;

	assert(out && ancestor && ours && theirs);
	
	memset(out, 0x0, sizeof(git_filediff_result));

	if (!GIT_FILEDIFF_FILE_EXISTS(ours) || !GIT_FILEDIFF_FILE_EXISTS(theirs))
		return 0;
	
	memset(&xmparam, 0x0, sizeof(xmparam_t));
	xmparam.ancestor = ancestor->label;
	xmparam.file1 = ours->label;
	xmparam.file2 = theirs->label;

	out->path = filediff_best_path(ancestor, ours, theirs);
	out->mode = filediff_best_mode(ancestor, ours, theirs);

	if (flags & GIT_FILEDIFF_FAVOR_OURS)
		xmparam.favor = XDL_MERGE_FAVOR_OURS;
		
	if (flags & GIT_FILEDIFF_FAVOR_THEIRS)
		xmparam.favor = XDL_MERGE_FAVOR_THEIRS;

	if ((xdl_result = xdl_merge(&ancestor->mmfile, &ours->mmfile,
		&theirs->mmfile, &xmparam, &mmbuffer)) < 0) {
		giterr_set(GITERR_MERGE, "Failed to merge files.");
		error = -1;
		goto done;
	}
	
	out->automergeable = (xdl_result == 0);
	out->data = (unsigned char *)mmbuffer.ptr;
	out->len = mmbuffer.size;

done:
	return error;
}


