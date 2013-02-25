#include "clar_libgit2.h"
#include "git2/tree.h"
#include "diff_tree.h"
#include "merge.h"

static git_repository *repo;

#define TEST_REPO_PATH "merge-resolve"

#define TREE_OID_ANCESTOR		"0d52e3a556e189ba0948ae56780918011c1b167d"
#define TREE_OID_MASTER			"1f81433e3161efbf250576c58fede7f6b836f3d3"
#define TREE_OID_BRANCH			"eea9286df54245fea72c5b557291470eb825f38f"
#define TREE_OID_RENAMES1		"f5f9dd5886a6ee20272be0aafc790cba43b31931"
#define TREE_OID_RENAMES2		"5fbfbdc04b4eca46f54f4853a3c5a1dce28f5165"

#define TREE_OID_DF_ANCESTOR	"b8a3a806d3950e8c0a03a34f234a92eff0e2c68d"
#define TREE_OID_DF_SIDE1		"ee1d6f164893c1866a323f072eeed36b855656be"
#define TREE_OID_DF_SIDE2		"6178885b38fe96e825ac0f492c0a941f288b37f6"

#define TREE_OID_RENAME_CONFLICT_ANCESTOR	"476dbb3e207313d1d8aaa120c6ad204bf1295e53"
#define TREE_OID_RENAME_CONFLICT_OURS		"c4efe31e9decccc8b2b4d3df9aac2cdfe2995618"
#define TREE_OID_RENAME_CONFLICT_THEIRS		"9e7f4359c469f309b6057febf4c6e80742cbed5b"

void test_merge_trees_treediff__initialize(void)
{
	repo = cl_git_sandbox_init(TEST_REPO_PATH);
}

void test_merge_trees_treediff__cleanup(void)
{
	cl_git_sandbox_cleanup();
}

struct treediff_file_data {
    uint16_t mode;
    char path[128];
    char oid_str[41];
    unsigned int status;
};

struct treediff_delta_data {
	struct treediff_file_data ancestor;
	struct treediff_file_data ours;
	struct treediff_file_data theirs;
	git_merge_conflict_type_t conflict_type;
};

struct treediff_cb_data {
    struct treediff_delta_data *delta_data;
    size_t delta_data_len;

    size_t idx;
};

static bool treediff_cmp(
	const git_index_entry *diff_file,
	const git_delta_t diff_status,
	const struct treediff_file_data *expected)
{
	git_oid oid;

	if (expected->mode == 0) {
		if (diff_file->path != NULL)
			return 0;
	} else {
		if (diff_file->path == NULL)
			return 0;
		
		cl_git_pass(git_oid_fromstr(&oid, expected->oid_str));

		if (strcmp(expected->path, diff_file->path) != 0 ||
			git_oid_cmp(&oid, &diff_file->oid) != 0)
			return 0;
	}

	if (expected->status != diff_status)
		return 0;
	
	return 1;
}

static int treediff_cb(const git_merge_index_conflict *delta, void *cb_data)
{
    struct treediff_cb_data *treediff_cb_data = cb_data;
	struct treediff_delta_data *delta_data = &treediff_cb_data->delta_data[treediff_cb_data->idx];
    
	cl_assert(treediff_cmp(&delta->ancestor_entry, 0, &delta_data->ancestor));
	cl_assert(treediff_cmp(&delta->our_entry, delta->our_status, &delta_data->ours));
	cl_assert(treediff_cmp(&delta->their_entry, delta->their_status, &delta_data->theirs));
	
	cl_assert(delta->type == delta_data->conflict_type);

    treediff_cb_data->idx++;
    
    return 0;
}

typedef int (*git_diff_tree_delta_cb)(const git_merge_index_conflict *delta, void *payload);

static int git_diff_tree_foreach(
	git_merge_index *diff_tree,
	git_diff_tree_delta_cb callback,
	void *payload)
{
	git_merge_index_conflict *delta;
	size_t i;
	int error = 0;

	assert (diff_tree && callback);

	git_vector_foreach(&diff_tree->conflicts, i, delta) {
		if (callback(delta, payload) != 0) {
			error = GIT_EUSER;
			break;
		}
	}

	return error;
}

static git_merge_index *threeway(
    const char *ancestor_oidstr,
    const char *ours_oidstr,
    const char *theirs_oidstr,
    struct treediff_delta_data *treediff_delta_data,
    size_t treediff_delta_data_len)
{
    git_merge_index *diff_tree = git_merge_index__alloc(repo);
    git_oid ancestor_oid, ours_oid, theirs_oid;
    git_tree *ancestor_tree, *ours_tree, *theirs_tree;
    struct treediff_cb_data treediff_cb_data = {0};

	git_merge_tree_opts opts = GIT_MERGE_TREE_OPTS_INIT;
	opts.flags |= GIT_MERGE_TREE_FIND_RENAMES;
	opts.rename_threshold = 50;

    cl_git_pass(git_oid_fromstr(&ancestor_oid, ancestor_oidstr));
    cl_git_pass(git_oid_fromstr(&ours_oid, ours_oidstr));
    cl_git_pass(git_oid_fromstr(&theirs_oid, theirs_oidstr));
    
    cl_git_pass(git_tree_lookup(&ancestor_tree, repo, &ancestor_oid));
    cl_git_pass(git_tree_lookup(&ours_tree, repo, &ours_oid));
    cl_git_pass(git_tree_lookup(&theirs_tree, repo, &theirs_oid));
    
	cl_git_pass(git_diff_trees(diff_tree, ancestor_tree, ours_tree, theirs_tree, &opts));

    cl_assert(treediff_delta_data_len == diff_tree->conflicts.length);
    
    treediff_cb_data.delta_data = treediff_delta_data;
	treediff_cb_data.delta_data_len = treediff_delta_data_len;
    
    cl_git_pass(git_diff_tree_foreach(diff_tree, treediff_cb, &treediff_cb_data));
    
    git_tree_free(ancestor_tree);
    git_tree_free(ours_tree);
    git_tree_free(theirs_tree);
    
    return diff_tree;
}

void test_merge_trees_treediff__simple(void)
{
    git_merge_index *diff_tree;
    
    struct treediff_delta_data treediff_delta_data[] = {
		{
			{ 0, "", "", GIT_DELTA_UNMODIFIED },
			{ 0100644, "added-in-master.txt", "233c0919c998ed110a4b6ff36f353aec8b713487", GIT_DELTA_ADDED },
			{ 0, "", "", GIT_DELTA_UNMODIFIED },
			GIT_MERGE_CONFLICT_NONE
		},

        {
			{ 0100644, "automergeable.txt", "6212c31dab5e482247d7977e4f0dd3601decf13b", GIT_DELTA_UNMODIFIED },
			{ 0100644, "automergeable.txt", "ee3fa1b8c00aff7fe02065fdb50864bb0d932ccf", GIT_DELTA_MODIFIED },
			{ 0100644, "automergeable.txt", "058541fc37114bfc1dddf6bd6bffc7fae5c2e6fe", GIT_DELTA_MODIFIED },
			GIT_MERGE_CONFLICT_BOTH_MODIFIED
		},
		
		{
			{ 0100644, "changed-in-branch.txt", "ab6c44a2e84492ad4b41bb6bac87353e9d02ac8b", GIT_DELTA_UNMODIFIED },
			{ 0100644, "changed-in-branch.txt", "ab6c44a2e84492ad4b41bb6bac87353e9d02ac8b", GIT_DELTA_UNMODIFIED },
			{ 0100644, "changed-in-branch.txt", "4eb04c9e79e88f6640d01ff5b25ca2a60764f216", GIT_DELTA_MODIFIED },
			GIT_MERGE_CONFLICT_NONE
		},
		
		{
			{ 0100644, "changed-in-master.txt", "ab6c44a2e84492ad4b41bb6bac87353e9d02ac8b", GIT_DELTA_UNMODIFIED },
			{ 0100644, "changed-in-master.txt", "11deab00b2d3a6f5a3073988ac050c2d7b6655e2", GIT_DELTA_MODIFIED },
			{ 0100644, "changed-in-master.txt", "ab6c44a2e84492ad4b41bb6bac87353e9d02ac8b", GIT_DELTA_UNMODIFIED },
			GIT_MERGE_CONFLICT_NONE
        },
		
		{
			{ 0100644, "conflicting.txt", "d427e0b2e138501a3d15cc376077a3631e15bd46", GIT_DELTA_UNMODIFIED },
			{ 0100644, "conflicting.txt", "4e886e602529caa9ab11d71f86634bd1b6e0de10", GIT_DELTA_MODIFIED },
			{ 0100644, "conflicting.txt", "2bd0a343aeef7a2cf0d158478966a6e587ff3863", GIT_DELTA_MODIFIED },
			GIT_MERGE_CONFLICT_BOTH_MODIFIED
        },
		
		{
			{ 0100644, "removed-in-branch.txt", "dfe3f22baa1f6fce5447901c3086bae368de6bdd", GIT_DELTA_UNMODIFIED },
			{ 0100644, "removed-in-branch.txt", "dfe3f22baa1f6fce5447901c3086bae368de6bdd", GIT_DELTA_UNMODIFIED },
			{ 0, "", "", GIT_DELTA_DELETED },
			GIT_MERGE_CONFLICT_NONE
        },
		
		{
			{ 0100644, "removed-in-master.txt", "5c3b68a71fc4fa5d362fd3875e53137c6a5ab7a5", GIT_DELTA_UNMODIFIED },
			{ 0, "", "", GIT_DELTA_DELETED },
			{ 0100644, "removed-in-master.txt", "5c3b68a71fc4fa5d362fd3875e53137c6a5ab7a5", GIT_DELTA_UNMODIFIED },
			GIT_MERGE_CONFLICT_NONE
		},
    };
    
    cl_assert(diff_tree = threeway(TREE_OID_ANCESTOR, TREE_OID_MASTER, TREE_OID_BRANCH, treediff_delta_data, 7));
    
    git_merge_index_free(diff_tree);
}

void test_merge_trees_treediff__df_conflicts(void)
{
	git_merge_index *diff_tree;
	
    struct treediff_delta_data treediff_delta_data[] = {
		{
			{ 0, "", "", GIT_DELTA_UNMODIFIED },
			{ 0100644, "dir-10", "49130a28ef567af9a6a6104c38773fedfa5f9742", GIT_DELTA_ADDED },
			{ 0100644, "dir-10", "6c06dcd163587c2cc18be44857e0b71116382aeb", GIT_DELTA_ADDED },
			GIT_MERGE_CONFLICT_BOTH_ADDED,
		},

		{
			{ 0100644, "dir-10/file.txt", "242591eb280ee9eeb2ce63524b9a8b9bc4cb515d", GIT_DELTA_UNMODIFIED },
			{ 0, "", "", GIT_DELTA_DELETED },
			{ 0, "", "", GIT_DELTA_DELETED },
			GIT_MERGE_CONFLICT_BOTH_DELETED,
		},
		
		{
			{ 0, "", "", GIT_DELTA_UNMODIFIED },
			{ 0, "", "", GIT_DELTA_UNMODIFIED },
			{ 0100644, "dir-6", "43aafd43bea779ec74317dc361f45ae3f532a505", GIT_DELTA_ADDED },
			GIT_MERGE_CONFLICT_NONE,
		},

		{
			{ 0100644, "dir-6/file.txt", "cf8c5cc8a85a1ff5a4ba51e0bc7cf5665669924d", GIT_DELTA_UNMODIFIED },
			{ 0100644, "dir-6/file.txt", "cf8c5cc8a85a1ff5a4ba51e0bc7cf5665669924d", GIT_DELTA_UNMODIFIED },
			{ 0, "", "", GIT_DELTA_DELETED },
			GIT_MERGE_CONFLICT_NONE,
		},
		
		{
			{ 0, "", "", GIT_DELTA_UNMODIFIED },
			{ 0, "", "", GIT_DELTA_UNMODIFIED },
			{ 0100644, "dir-7", "a031a28ae70e33a641ce4b8a8f6317f1ab79dee4", GIT_DELTA_ADDED },
			GIT_MERGE_CONFLICT_DIRECTORY_FILE,
		},

		{
			{ 0100644, "dir-7/file.txt", "5012fd565b1393bdfda1805d4ec38ce6619e1fd1", GIT_DELTA_UNMODIFIED },
			{ 0100644, "dir-7/file.txt", "a5563304ddf6caba25cb50323a2ea6f7dbfcadca", GIT_DELTA_MODIFIED },
			{ 0, "", "", GIT_DELTA_DELETED },
			GIT_MERGE_CONFLICT_DF_CHILD,
		},
		
		{
			{ 0, "", "", GIT_DELTA_UNMODIFIED },
			{ 0100644, "dir-8", "e9ad6ec3e38364a3d07feda7c4197d4d845c53b5", GIT_DELTA_ADDED },
			{ 0, "", "", GIT_DELTA_UNMODIFIED },
			GIT_MERGE_CONFLICT_NONE,
		},

		{
			{ 0100644, "dir-8/file.txt", "f20c9063fa0bda9a397c96947a7b687305c49753", GIT_DELTA_UNMODIFIED },
			{ 0, "", "", GIT_DELTA_DELETED },
			{ 0100644, "dir-8/file.txt", "f20c9063fa0bda9a397c96947a7b687305c49753", GIT_DELTA_UNMODIFIED },
			GIT_MERGE_CONFLICT_NONE,
		},
		
		{
			{ 0, "", "", GIT_DELTA_UNMODIFIED },
			{ 0100644, "dir-9", "3ef4d30382ca33fdeba9fda895a99e0891ba37aa", GIT_DELTA_ADDED },
			{ 0, "", "", GIT_DELTA_UNMODIFIED },
			GIT_MERGE_CONFLICT_DIRECTORY_FILE,
		},

		{
			{ 0100644, "dir-9/file.txt", "fc4c636d6515e9e261f9260dbcf3cc6eca97ea08", GIT_DELTA_UNMODIFIED },
			{ 0, "", "", GIT_DELTA_DELETED },
			{ 0100644, "dir-9/file.txt", "76ab0e2868197ec158ddd6c78d8a0d2fd73d38f9", GIT_DELTA_MODIFIED },
			GIT_MERGE_CONFLICT_DF_CHILD,
		},

		{
			{ 0100644, "file-1", "1e4ff029aee68d0d69ef9eb6efa6cbf1ec732f99", GIT_DELTA_UNMODIFIED },
			{ 0100644, "file-1", "1e4ff029aee68d0d69ef9eb6efa6cbf1ec732f99", GIT_DELTA_UNMODIFIED },
			{ 0, "", "", GIT_DELTA_DELETED },
			GIT_MERGE_CONFLICT_NONE,
		},

		{
			{ 0, "", "", GIT_DELTA_UNMODIFIED },
			{ 0, "", "", GIT_DELTA_UNMODIFIED },
			{ 0100644, "file-1/new", "5c2411f8075f48a6b2fdb85ebc0d371747c4df15", GIT_DELTA_ADDED },
			GIT_MERGE_CONFLICT_NONE,
		},

		{
			{ 0100644, "file-2", "a39a620dae5bc8b4e771cd4d251b7d080401a21e", GIT_DELTA_UNMODIFIED },
			{ 0100644, "file-2", "d963979c237d08b6ba39062ee7bf64c7d34a27f8", GIT_DELTA_MODIFIED },
			{ 0, "", "", GIT_DELTA_DELETED },
			GIT_MERGE_CONFLICT_DIRECTORY_FILE,
		},
		
		{
			{ 0, "", "", GIT_DELTA_UNMODIFIED },
			{ 0, "", "", GIT_DELTA_UNMODIFIED },
			{ 0100644, "file-2/new", "5c341ead2ba6f2af98ce5ec3fe84f6b6d2899c0d", GIT_DELTA_ADDED },
			GIT_MERGE_CONFLICT_DF_CHILD,
		},

		{
			{ 0100644, "file-3", "032ebc5ab85d9553bb187d3cd40875ff23a63ed0", GIT_DELTA_UNMODIFIED },
			{ 0, "", "", GIT_DELTA_DELETED },
			{ 0100644, "file-3", "032ebc5ab85d9553bb187d3cd40875ff23a63ed0", GIT_DELTA_UNMODIFIED },
			GIT_MERGE_CONFLICT_NONE,
		},

		{
			{ 0, "", "", GIT_DELTA_UNMODIFIED },
			{ 0100644, "file-3/new", "9efe7723802d4305142eee177e018fee1572c4f4", GIT_DELTA_ADDED },
			{ 0, "", "", GIT_DELTA_UNMODIFIED },
			GIT_MERGE_CONFLICT_NONE,
		},

		{
			{ 0100644, "file-4", "bacac9b3493509aa15e1730e1545fc0919d1dae0", GIT_DELTA_UNMODIFIED },
			{ 0, "", "", GIT_DELTA_DELETED },
			{ 0100644, "file-4", "7663fce0130db092936b137cabd693ec234eb060", GIT_DELTA_MODIFIED },
			GIT_MERGE_CONFLICT_DIRECTORY_FILE,
		},

		{
			{ 0, "", "", GIT_DELTA_UNMODIFIED },
			{ 0100644, "file-4/new", "e49f917b448d1340b31d76e54ba388268fd4c922", GIT_DELTA_ADDED },
			{ 0, "", "", GIT_DELTA_UNMODIFIED },
			GIT_MERGE_CONFLICT_DF_CHILD,
		},

		{
			{ 0100644, "file-5", "ac4045f965119e6998f4340ed0f411decfb3ec05", GIT_DELTA_UNMODIFIED },
			{ 0, "", "", GIT_DELTA_DELETED },
			{ 0, "", "", GIT_DELTA_DELETED },
			GIT_MERGE_CONFLICT_BOTH_DELETED,
		},
		
		{
			{ 0, "", "", GIT_DELTA_UNMODIFIED },
			{ 0100644, "file-5/new", "cab2cf23998b40f1af2d9d9a756dc9e285a8df4b", GIT_DELTA_ADDED },
			{ 0100644, "file-5/new", "f5504f36e6f4eb797a56fc5bac6c6c7f32969bf2", GIT_DELTA_ADDED },
			GIT_MERGE_CONFLICT_BOTH_ADDED,
		},
	};
	
	cl_assert(diff_tree = threeway(TREE_OID_DF_ANCESTOR, TREE_OID_DF_SIDE1, TREE_OID_DF_SIDE2, treediff_delta_data, 20));
	
	git_merge_index_free(diff_tree);
}

void test_merge_trees_treediff__strict_renames(void)
{
    git_merge_index *diff_tree;
    
	struct treediff_delta_data treediff_delta_data[] = {
		{
			{ 0, "", "", GIT_DELTA_UNMODIFIED },
			{ 0100644, "added-in-master.txt", "233c0919c998ed110a4b6ff36f353aec8b713487", GIT_DELTA_ADDED },
			{ 0, "", "", GIT_DELTA_UNMODIFIED },
			GIT_MERGE_CONFLICT_NONE,
		},
        
		{
			{ 0100644, "automergeable.txt", "6212c31dab5e482247d7977e4f0dd3601decf13b", GIT_DELTA_UNMODIFIED },
			{ 0100644, "automergeable.txt", "ee3fa1b8c00aff7fe02065fdb50864bb0d932ccf", GIT_DELTA_MODIFIED },
			{ 0100644, "automergeable.txt", "6212c31dab5e482247d7977e4f0dd3601decf13b", GIT_DELTA_UNMODIFIED },
			GIT_MERGE_CONFLICT_NONE,
		},

		{
			{ 0100644, "changed-in-master.txt", "ab6c44a2e84492ad4b41bb6bac87353e9d02ac8b", GIT_DELTA_UNMODIFIED },
			{ 0100644, "changed-in-master.txt", "11deab00b2d3a6f5a3073988ac050c2d7b6655e2", GIT_DELTA_MODIFIED },
			{ 0100644, "changed-in-master.txt", "ab6c44a2e84492ad4b41bb6bac87353e9d02ac8b", GIT_DELTA_UNMODIFIED },
			GIT_MERGE_CONFLICT_NONE,
		},

		{
			{ 0100644, "conflicting.txt", "d427e0b2e138501a3d15cc376077a3631e15bd46", GIT_DELTA_UNMODIFIED },
			{ 0100644, "conflicting.txt", "4e886e602529caa9ab11d71f86634bd1b6e0de10", GIT_DELTA_MODIFIED },
			{ 0100644, "conflicting.txt", "d427e0b2e138501a3d15cc376077a3631e15bd46", GIT_DELTA_UNMODIFIED },
			GIT_MERGE_CONFLICT_NONE,
		},

		{
			{ 0100644, "removed-in-branch.txt", "dfe3f22baa1f6fce5447901c3086bae368de6bdd", GIT_DELTA_UNMODIFIED },
			{ 0100644, "removed-in-branch.txt", "dfe3f22baa1f6fce5447901c3086bae368de6bdd", GIT_DELTA_UNMODIFIED },
			{ 0100644, "renamed-in-branch.txt", "dfe3f22baa1f6fce5447901c3086bae368de6bdd", GIT_DELTA_RENAMED },
			GIT_MERGE_CONFLICT_NONE,
		},

		{
			{ 0100644, "removed-in-master.txt", "5c3b68a71fc4fa5d362fd3875e53137c6a5ab7a5", GIT_DELTA_UNMODIFIED },
			{ 0, "", "", GIT_DELTA_DELETED },
			{ 0100644, "removed-in-master.txt", "5c3b68a71fc4fa5d362fd3875e53137c6a5ab7a5", GIT_DELTA_UNMODIFIED },
			GIT_MERGE_CONFLICT_NONE,
		},

		{
			{ 0, "", "", GIT_DELTA_UNMODIFIED },
			{ 0, "", "", GIT_DELTA_UNMODIFIED },
			{ 0100644, "renamed.txt", "c8f06f2e3bb2964174677e91f0abead0e43c9e5d", GIT_DELTA_ADDED },
			GIT_MERGE_CONFLICT_NONE,
		},

		{
			{ 0100644, "unchanged.txt", "c8f06f2e3bb2964174677e91f0abead0e43c9e5d", GIT_DELTA_UNMODIFIED },
			{ 0100644, "unchanged.txt", "c8f06f2e3bb2964174677e91f0abead0e43c9e5d", GIT_DELTA_UNMODIFIED },
			{ 0100644, "copied.txt", "c8f06f2e3bb2964174677e91f0abead0e43c9e5d", GIT_DELTA_RENAMED },
			GIT_MERGE_CONFLICT_NONE,
		},
    };
    
    cl_assert(diff_tree = threeway(TREE_OID_ANCESTOR, TREE_OID_MASTER, TREE_OID_RENAMES1, treediff_delta_data, 8));
    
    git_merge_index_free(diff_tree);
}

void test_merge_trees_treediff__rename_conflicts(void)
{
    git_merge_index *diff_tree;
    
	struct treediff_delta_data treediff_delta_data[] = {
		{
			{ 0, "", "", GIT_DELTA_UNMODIFIED },
			{ 0100644, "0b-duplicated-in-ours.txt", "f0ce2b8e4986084d9b308fb72709e414c23eb5e6", GIT_DELTA_ADDED },
			{ 0, "", "", GIT_DELTA_UNMODIFIED },
			GIT_MERGE_CONFLICT_NONE,
		},

		{
			{ 0100644, "0b-rewritten-in-ours.txt", "f0ce2b8e4986084d9b308fb72709e414c23eb5e6", GIT_DELTA_UNMODIFIED },
			{ 0100644, "0b-rewritten-in-ours.txt", "e376fbdd06ebf021c92724da9f26f44212734e3e", GIT_DELTA_MODIFIED },
			{ 0100644, "0b-rewritten-in-ours.txt", "b2d399ae15224e1d58066e3c8df70ce37de7a656", GIT_DELTA_MODIFIED },
			GIT_MERGE_CONFLICT_BOTH_MODIFIED,
		},

		{
			{ 0, "", "", GIT_DELTA_UNMODIFIED },
			{ 0, "", "", GIT_DELTA_UNMODIFIED },
			{ 0100644, "0c-duplicated-in-theirs.txt", "2f56120107d680129a5d9791b521cb1e73a2ed31", GIT_DELTA_ADDED },
			GIT_MERGE_CONFLICT_NONE,
		},
		
		{
			{ 0100644, "0c-rewritten-in-theirs.txt", "2f56120107d680129a5d9791b521cb1e73a2ed31", GIT_DELTA_UNMODIFIED },
			{ 0100644, "0c-rewritten-in-theirs.txt", "efc9121fdedaf08ba180b53ebfbcf71bd488ed09", GIT_DELTA_MODIFIED },
			{ 0100644, "0c-rewritten-in-theirs.txt", "712ebba6669ea847d9829e4f1059d6c830c8b531", GIT_DELTA_MODIFIED },
			GIT_MERGE_CONFLICT_BOTH_MODIFIED,
		},

		{
			{ 0100644, "1a-renamed-in-ours-edited-in-theirs.txt", "c3d02eeef75183df7584d8d13ac03053910c1301", GIT_DELTA_UNMODIFIED },
			{ 0100644, "1a-newname-in-ours-edited-in-theirs.txt", "c3d02eeef75183df7584d8d13ac03053910c1301", GIT_DELTA_RENAMED },
			{ 0100644, "1a-renamed-in-ours-edited-in-theirs.txt", "0d872f8e871a30208305978ecbf9e66d864f1638", GIT_DELTA_MODIFIED },
			GIT_MERGE_CONFLICT_RENAMED_MODIFIED,
		},
		
		{
			{ 0100644, "1a-renamed-in-ours.txt", "d0d4594e16f2e19107e3fa7ea63e7aaaff305ffb", GIT_DELTA_UNMODIFIED },
			{ 0100644, "1a-newname-in-ours.txt", "d0d4594e16f2e19107e3fa7ea63e7aaaff305ffb", GIT_DELTA_RENAMED },
			{ 0100644, "1a-renamed-in-ours.txt", "d0d4594e16f2e19107e3fa7ea63e7aaaff305ffb", GIT_DELTA_UNMODIFIED },
			GIT_MERGE_CONFLICT_NONE,
		},
		
		{
			{ 0100644, "1b-renamed-in-theirs-edited-in-ours.txt", "241a1005cd9b980732741b74385b891142bcba28", GIT_DELTA_UNMODIFIED },
			{ 0100644, "1b-renamed-in-theirs-edited-in-ours.txt", "ed9523e62e453e50dd9be1606af19399b96e397a", GIT_DELTA_MODIFIED },
			{ 0100644, "1b-newname-in-theirs-edited-in-ours.txt", "241a1005cd9b980732741b74385b891142bcba28", GIT_DELTA_RENAMED },
			GIT_MERGE_CONFLICT_RENAMED_MODIFIED,
		},
		
		{
			{ 0100644, "1b-renamed-in-theirs.txt", "2b5f1f181ee3b58ea751f5dd5d8f9b445520a136", GIT_DELTA_UNMODIFIED },
			{ 0100644, "1b-renamed-in-theirs.txt", "2b5f1f181ee3b58ea751f5dd5d8f9b445520a136", GIT_DELTA_UNMODIFIED },
			{ 0100644, "1b-newname-in-theirs.txt", "2b5f1f181ee3b58ea751f5dd5d8f9b445520a136", GIT_DELTA_RENAMED },
			GIT_MERGE_CONFLICT_NONE,
		},

		{
			{ 0100644, "2-renamed-in-both.txt", "178940b450f238a56c0d75b7955cb57b38191982", GIT_DELTA_UNMODIFIED },
			{ 0100644, "2-newname-in-both.txt", "178940b450f238a56c0d75b7955cb57b38191982", GIT_DELTA_RENAMED },
			{ 0100644, "2-newname-in-both.txt", "178940b450f238a56c0d75b7955cb57b38191982", GIT_DELTA_RENAMED },
			GIT_MERGE_CONFLICT_BOTH_RENAMED,
		},
		
		{
			{ 0100644, "3a-renamed-in-ours-deleted-in-theirs.txt", "18cb316b1cefa0f8a6946f0e201a8e1a6f845ab9", GIT_DELTA_UNMODIFIED },
			{ 0100644, "3a-newname-in-ours-deleted-in-theirs.txt", "18cb316b1cefa0f8a6946f0e201a8e1a6f845ab9", GIT_DELTA_RENAMED },
			{ 0, "", "", GIT_DELTA_DELETED },
			GIT_MERGE_CONFLICT_RENAMED_DELETED,
		},
		
		{
			{ 0100644, "3b-renamed-in-theirs-deleted-in-ours.txt", "36219b49367146cb2e6a1555b5a9ebd4d0328495", GIT_DELTA_UNMODIFIED },
			{ 0, "", "", GIT_DELTA_DELETED },
			{ 0100644, "3b-newname-in-theirs-deleted-in-ours.txt", "36219b49367146cb2e6a1555b5a9ebd4d0328495", GIT_DELTA_RENAMED },
			GIT_MERGE_CONFLICT_RENAMED_DELETED,
		},
		
		{
			{ 0, "", "", GIT_DELTA_UNMODIFIED },
			{ 0, "", "", GIT_DELTA_UNMODIFIED },
			{ 0100644, "4a-newname-in-ours-added-in-theirs.txt", "8b5b53cb2aa9ceb1139f5312fcfa3cc3c5a47c9a", GIT_DELTA_ADDED },
			GIT_MERGE_CONFLICT_RENAMED_ADDED,
		},		
		
		{
			{ 0100644, "4a-renamed-in-ours-added-in-theirs.txt", "227792b52aaa0b238bea00ec7e509b02623f168c", GIT_DELTA_UNMODIFIED },
			{ 0100644, "4a-newname-in-ours-added-in-theirs.txt", "227792b52aaa0b238bea00ec7e509b02623f168c", GIT_DELTA_RENAMED },
			{ 0, "", "", GIT_DELTA_DELETED },
			GIT_MERGE_CONFLICT_RENAMED_ADDED,
		},

		{
			{ 0, "", "", GIT_DELTA_UNMODIFIED },
			{ 0100644, "4b-newname-in-theirs-added-in-ours.txt", "de872ee3618b894992e9d1e18ba2ebe256a112f9", GIT_DELTA_ADDED },
			{ 0, "", "", GIT_DELTA_UNMODIFIED },
			GIT_MERGE_CONFLICT_RENAMED_ADDED,
		},

		{
			{ 0100644, "4b-renamed-in-theirs-added-in-ours.txt", "98d52d07c0b0bbf2b46548f6aa521295c2cb55db", GIT_DELTA_UNMODIFIED },
			{ 0, "", "", GIT_DELTA_DELETED },
			{ 0100644, "4b-newname-in-theirs-added-in-ours.txt", "98d52d07c0b0bbf2b46548f6aa521295c2cb55db", GIT_DELTA_RENAMED },
			GIT_MERGE_CONFLICT_RENAMED_ADDED,
		},
		
		{
			{ 0100644, "5-both-renamed-1-to-2.txt", "d8fa77b6833082c1ea36b7828a582d4c43882450", GIT_DELTA_UNMODIFIED },
			{ 0100644, "5-both-renamed-1-to-2-ours.txt", "d8fa77b6833082c1ea36b7828a582d4c43882450", GIT_DELTA_RENAMED },
			{ 0100644, "5-both-renamed-1-to-2-theirs.txt", "d8fa77b6833082c1ea36b7828a582d4c43882450", GIT_DELTA_RENAMED },
			GIT_MERGE_CONFLICT_BOTH_RENAMED_1_TO_2,
		},
		
		{

			{ 0100644, "6-both-renamed-side-1.txt", "b42712cfe99a1a500b2a51fe984e0b8a7702ba11", GIT_DELTA_UNMODIFIED },
			{ 0100644, "6-both-renamed.txt", "b42712cfe99a1a500b2a51fe984e0b8a7702ba11", GIT_DELTA_RENAMED },
			{ 0100644, "6-both-renamed-side-1.txt", "b42712cfe99a1a500b2a51fe984e0b8a7702ba11", GIT_DELTA_UNMODIFIED },
			GIT_MERGE_CONFLICT_BOTH_RENAMED_2_TO_1,
		},
		
		{
			{ 0100644, "6-both-renamed-side-2.txt", "b69fe837e4cecfd4c9a40cdca7c138468687df07", GIT_DELTA_UNMODIFIED },
			{ 0100644, "6-both-renamed-side-2.txt", "b69fe837e4cecfd4c9a40cdca7c138468687df07", GIT_DELTA_UNMODIFIED },
			{ 0100644, "6-both-renamed.txt", "b69fe837e4cecfd4c9a40cdca7c138468687df07", GIT_DELTA_RENAMED },
			GIT_MERGE_CONFLICT_BOTH_RENAMED_2_TO_1,
		},
    };
    
    cl_assert(diff_tree = threeway(TREE_OID_RENAME_CONFLICT_ANCESTOR, TREE_OID_RENAME_CONFLICT_OURS, TREE_OID_RENAME_CONFLICT_THEIRS, treediff_delta_data, 18));
    
    git_merge_index_free(diff_tree);
}

/*
 * TODO: enable this when diff computation is implemented.
 *
void test_merge_trees_treediff__best_renames(void)
{
    git_diff_tree_list *diff_tree;
    
    struct treediff_file_data treediff_file_data[] = {
        { 0, "", "", GIT_DELTA_UNMODIFIED },
        { 0100644, "added-in-master.txt", "233c0919c998ed110a4b6ff36f353aec8b713487", GIT_DELTA_ADDED },
        { 0, "", "", GIT_DELTA_UNMODIFIED },
        
        { 0100644, "automergeable.txt", "6212c31dab5e482247d7977e4f0dd3601decf13b", GIT_DELTA_UNMODIFIED },
        { 0100644, "automergeable.txt", "ee3fa1b8c00aff7fe02065fdb50864bb0d932ccf", GIT_DELTA_MODIFIED },
        { 0100644, "renamed-90.txt", "45299c1ca5e07bba1fd90843056fb559f96b1f5a", GIT_DELTA_RENAMED },
        
        { 0100644, "changed-in-master.txt", "ab6c44a2e84492ad4b41bb6bac87353e9d02ac8b", GIT_DELTA_UNMODIFIED },
        { 0100644, "changed-in-master.txt", "11deab00b2d3a6f5a3073988ac050c2d7b6655e2", GIT_DELTA_MODIFIED },
        { 0100644, "changed-in-master.txt", "ab6c44a2e84492ad4b41bb6bac87353e9d02ac8b", GIT_DELTA_UNMODIFIED },
        
        { 0100644, "conflicting.txt", "d427e0b2e138501a3d15cc376077a3631e15bd46", GIT_DELTA_UNMODIFIED },
        { 0100644, "conflicting.txt", "4e886e602529caa9ab11d71f86634bd1b6e0de10", GIT_DELTA_MODIFIED },
        { 0100644, "conflicting.txt", "d427e0b2e138501a3d15cc376077a3631e15bd46", GIT_DELTA_UNMODIFIED },

        { 0100644, "removed-in-master.txt", "5c3b68a71fc4fa5d362fd3875e53137c6a5ab7a5", GIT_DELTA_UNMODIFIED },
        { 0, "", "", GIT_DELTA_DELETED },
        { 0100644, "removed-in-master.txt", "5c3b68a71fc4fa5d362fd3875e53137c6a5ab7a5", GIT_DELTA_UNMODIFIED },
        
        { 0, "", "", GIT_DELTA_UNMODIFIED },
        { 0, "", "", GIT_DELTA_UNMODIFIED },
        { 0100644, "renamed-50.txt", "5843febcb23480df0b5edb22a21c59c772bb8e29", GIT_DELTA_ADDED },
        
        { 0, "", "", GIT_DELTA_UNMODIFIED },
        { 0, "", "", GIT_DELTA_UNMODIFIED },
        { 0100644, "renamed-75.txt", "a77a56a49f8f3ae242e02717f18ebbc60c5cc543", GIT_DELTA_ADDED },        
    };
    
    cl_assert(diff_tree = threeway(TREE_OID_ANCESTOR, TREE_OID_MASTER, TREE_OID_RENAMES2, treediff_file_data, 7));
    
    git_diff_tree_list_free(diff_tree);
}
*/
