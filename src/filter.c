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
#include "blob.h"
#include "git2/config.h"
#include "git2/sys/filter.h"

int git_filters_load(git_vector *filters, git_repository *repo, const char *path, int mode)
{
	git_filter *filter;
	size_t i;
	int error, count = 0;

	git_vector_foreach(&repo->filters, i, filter) {
		if (filter->should_apply(filter, path, mode)) {
			if ((error = git_vector_insert(filters, filter)) < 0)
				return error;
			
			++count;
		}
	}

	return count;
}

int git_filters_apply(
	git_filterbuf **out,
	git_vector *filters,
	const char *path,
	git_filter_mode_t mode,
	const void *src,
	size_t src_len)
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
		if ((error = filter->apply(&dst, &dst_len, filter, path, mode, in, in_len)) < 0)
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
