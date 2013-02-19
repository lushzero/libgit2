/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_filediff_h__
#define INCLUDE_filediff_h__

#include "diff_tree.h"
#include "xdiff/xdiff.h"

#include "git2/diff_tree.h"

typedef struct git_filediff_input {
	const char *label;
	const char *path;
	unsigned int mode;
	mmfile_t mmfile;
	
	void (*close)(struct git_filediff_input *input);
} git_filediff_input;

typedef struct {
	git_filediff_input base;
	git_odb_object *odb_object;
} git_filediff_index_input;

#define GIT_FILEDIFF_INPUT_INIT		{ {0} }

typedef struct {
	bool automergeable;
	
	const char *path;
	int mode;
	
	unsigned char *data;
	size_t len;
} git_filediff_result;

#define GIT_FILEDIFF_RESULT_INIT	{0}

typedef enum {
	GIT_FILEDIFF_NONE = 0,
	GIT_FILEDIFF_FAVOR_OURS = (1 << 1),
	GIT_FILEDIFF_FAVOR_THEIRS = (1 << 2),
} git_filediff_flags;

GIT_INLINE(void) git_filediff_index_input_close(git_filediff_input *_input)
{
	git_filediff_index_input *input = (git_filediff_index_input *)_input;
	git_odb_object_free(input->odb_object);
}

GIT_INLINE(int) git_filediff_input_from_index_entry(
	git_filediff_index_input *input,
	git_repository *repo,
	const git_index_entry *entry)
{
	git_odb *odb = NULL;
	git_odb_object *odb_object = NULL;
	int error = 0;
	
	assert(input && repo && entry);
	
	if (entry->mode == 0)
		return 0;

	if ((error = git_repository_odb(&odb, repo)) < 0 ||
		(error = git_odb_read(&input->odb_object, odb, &entry->oid)) < 0)
		goto done;
	
	input->base.mode = entry->mode;
	input->base.path = entry->path;
	input->base.mmfile.size = git_odb_object_size(odb_object);
	input->base.mmfile.ptr = (char *)git_odb_object_data(odb_object);
	
	if (input->base.label == NULL)
		input->base.label = entry->path;
	
	input->base.close = git_filediff_index_input_close;
	
done:
	git_odb_free(odb);
	
	return error;
}

GIT_INLINE(int) git_filediff_input_from_diff_tree_entry(
	git_filediff_index_input *input,
	git_repository *repo,
	const git_diff_tree_entry *entry)
{
	git_odb *odb = NULL;
	int error = 0;
	
	assert(input && repo && entry);
	
	if (entry->file.mode == 0)
		return 0;

	if ((error = git_repository_odb(&odb, repo)) < 0 ||
		(error = git_odb_read(&input->odb_object, odb, &entry->file.oid)) < 0)
		goto done;
	
	input->base.mode = entry->file.mode;
	input->base.path = entry->file.path;
	input->base.mmfile.size = git_odb_object_size(input->odb_object);
	input->base.mmfile.ptr = (char *)git_odb_object_data(input->odb_object);
	
	if (input->base.label == NULL)
		input->base.label = entry->file.path;
	
	input->base.close = git_filediff_index_input_close;
	
done:
	git_odb_free(odb);
	
	return error;
}

GIT_INLINE(void) git_filediff_input_free(git_filediff_input *input)
{
	assert(input);
	
	if (input->close)
		input->close(input);
}

int git_filediff(
	git_filediff_result *out,
	git_filediff_input *ancestor,
	git_filediff_input *ours,
	git_filediff_input *theirs,
	git_filediff_flags flags);

GIT_INLINE(void) git_filediff_result_free(git_filediff_result *filediff)
{
	/* xdiff uses malloc() not git_malloc, so we use free(), not git_free() */
	if (filediff->data != NULL)
		free(filediff->data);
}
#endif
