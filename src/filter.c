/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "common.h"
#include "fileops.h"
#include "hash.h"
#include "filter.h"
#include "repository.h"
#include "git2/config.h"
#include "blob.h"

int git_filters_load(git_vector *filters, git_repository *repo, const char *path, int mode)
{
	int error;

	if (mode == GIT_FILTER_TO_ODB) {
		/* Load the CRLF cleanup filter when writing to the ODB */
		error = git_filter_add__crlf_to_odb(filters, repo, path);
		if (error < 0)
			return error;
	} else {
		error = git_filter_add__crlf_to_workdir(filters, repo, path);
		if (error < 0)
			return error;
	}

	return (int)filters->length;
}

void git_filters_free(git_vector *filters)
{
	size_t i;
	git_filter *filter;

	git_vector_foreach(filters, i, filter) {
		if (filter->do_free != NULL)
			filter->do_free(filter);
		else
			git__free(filter);
	}

	git_vector_free(filters);
}

int git_filters_apply(git_filterbuf **out, git_vector *filters, const char *path, const void *src, size_t src_len)
{
	git_filter *filter;
	git_filterbuf *filterbuf;
	const void *in;
	void *dst = NULL;
	size_t in_len, dst_len;
	size_t i;
	int error = 0;
	int filtered = 0;

	*out = NULL;

	if (src_len == 0)
		return 0;

	if ((filterbuf = git__calloc(1, sizeof(git_filterbuf))) == NULL)
		return -1;

	in = src;
	in_len = src_len;

	git_vector_foreach(filters, i, filter) {
		if ((error = filter->apply(&dst, &dst_len, filter, path, in, in_len)) < 0)
			goto on_error;

		/* Filter cancelled application; do nothing. */
		if (error == 0)
			continue;

		if (filterbuf->ptr)
			filterbuf->free(filterbuf->ptr);

		filterbuf->ptr = dst;
		filterbuf->len = dst_len;
		filterbuf->free = filter->free_buf;

		filtered++;
	}

	if (filtered > 0)
		*out = filterbuf;

	return filtered;

on_error:
	git_filterbuf_free(filterbuf);
	return error;
}
