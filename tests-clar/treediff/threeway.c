#include "clar_libgit2.h"
#include "git2/diff_tree.h"
#include "git2/tree.h"
#include "diff_tree.h"

static git_repository *repo;

#define TEST_REPO_PATH "merge-resolve"

#define TREE_OID_ANCESTOR	"0d52e3a556e189ba0948ae56780918011c1b167d"
#define TREE_OID_MASTER		"1f81433e3161efbf250576c58fede7f6b836f3d3"
#define TREE_OID_BRANCH		"eea9286df54245fea72c5b557291470eb825f38f"
#define TREE_OID_RENAMES1   "f5f9dd5886a6ee20272be0aafc790cba43b31931"
#define TREE_OID_RENAMES2   "5fbfbdc04b4eca46f54f4853a3c5a1dce28f5165"

void test_treediff_threeway__initialize(void)
{
	repo = cl_git_sandbox_init(TEST_REPO_PATH);
}

void test_treediff_threeway__cleanup(void)
{
	cl_git_sandbox_cleanup();
}

struct treediff_file_data {
    uint16_t mode;
    char path[128];
    char oid_str[41];
    unsigned int status;
};

struct treediff_data {
    size_t trees_len;
    struct treediff_file_data *file_data;
    size_t file_data_len;

    size_t i;
};

static int treediff_cb(const git_diff_tree_delta *delta, void *cb_data)
{
    struct treediff_data *treediff_data = cb_data;
    git_diff_tree_entry const *tree_entries[3];
    size_t idx = treediff_data->i * treediff_data->trees_len;
    git_oid oid;
    size_t i;
    
    tree_entries[0] = &delta->ancestor;
    tree_entries[1] = &delta->ours;
    tree_entries[2] = &delta->theirs;
    
    for (i = 0; i < treediff_data->trees_len; i++) {
        if (treediff_data->file_data[idx+i].mode == 0) {
            if (tree_entries[i]->file.path != NULL)
                return -1;
        } else {
            if (tree_entries[i]->file.path == NULL)
                return -1;
            
            cl_git_pass(git_oid_fromstr(&oid, treediff_data->file_data[idx+i].oid_str));
            
            if (strcmp(treediff_data->file_data[idx+i].path, tree_entries[i]->file.path) != 0 ||
                git_oid_cmp(&oid, &tree_entries[i]->file.oid) != 0)
                return -1;
        }
        
        if (tree_entries[i]->status != treediff_data->file_data[idx+i].status)
            return -1;
    }
    
    treediff_data->i++;
    
    return 0;
}

static git_diff_tree_list *threeway(
    const char *ancestor_oidstr,
    const char *ours_oidstr,
    const char *theirs_oidstr,
    struct treediff_file_data *treediff_file_data,
    size_t treediff_file_data_len)
{
    git_diff_tree_list *diff_tree;
    git_oid ancestor_oid, ours_oid, theirs_oid;
    git_tree *ancestor_tree, *ours_tree, *theirs_tree;
    struct treediff_data treediff_data = {0};

    cl_git_pass(git_oid_fromstr(&ancestor_oid, ancestor_oidstr));
    cl_git_pass(git_oid_fromstr(&ours_oid, ours_oidstr));
    cl_git_pass(git_oid_fromstr(&theirs_oid, theirs_oidstr));
    
    cl_git_pass(git_tree_lookup(&ancestor_tree, repo, &ancestor_oid));
    cl_git_pass(git_tree_lookup(&ours_tree, repo, &ours_oid));
    cl_git_pass(git_tree_lookup(&theirs_tree, repo, &theirs_oid));
    
	cl_git_pass(git_diff_tree(&diff_tree, repo, ancestor_tree, ours_tree, theirs_tree, 0));

    cl_assert(treediff_file_data_len == diff_tree->deltas.length);
    
    treediff_data.trees_len = 3;
    treediff_data.file_data = treediff_file_data;
    
    cl_git_pass(git_diff_tree_foreach(diff_tree, treediff_cb, &treediff_data));
    
    git_tree_free(ancestor_tree);
    git_tree_free(ours_tree);
    git_tree_free(theirs_tree);
    
    return diff_tree;
}

void test_treediff_threeway__simple(void)
{
    git_diff_tree_list *diff_tree;
    
    struct treediff_file_data treediff_file_data[] = {
        { 0, "", "", GIT_DELTA_UNMODIFIED },
        { 0100644, "added-in-master.txt", "233c0919c998ed110a4b6ff36f353aec8b713487", GIT_DELTA_ADDED },
        { 0, "", "", GIT_DELTA_UNMODIFIED },
        
        { 0100644, "automergeable.txt", "6212c31dab5e482247d7977e4f0dd3601decf13b", GIT_DELTA_UNMODIFIED },
        { 0100644, "automergeable.txt", "ee3fa1b8c00aff7fe02065fdb50864bb0d932ccf", GIT_DELTA_MODIFIED },
        { 0100644, "automergeable.txt", "058541fc37114bfc1dddf6bd6bffc7fae5c2e6fe", GIT_DELTA_MODIFIED },
        
        { 0100644, "changed-in-branch.txt", "ab6c44a2e84492ad4b41bb6bac87353e9d02ac8b", GIT_DELTA_UNMODIFIED },
        { 0100644, "changed-in-branch.txt", "ab6c44a2e84492ad4b41bb6bac87353e9d02ac8b", GIT_DELTA_UNMODIFIED },
        { 0100644, "changed-in-branch.txt", "4eb04c9e79e88f6640d01ff5b25ca2a60764f216", GIT_DELTA_MODIFIED },
        
        { 0100644, "changed-in-master.txt", "ab6c44a2e84492ad4b41bb6bac87353e9d02ac8b", GIT_DELTA_UNMODIFIED },
        { 0100644, "changed-in-master.txt", "11deab00b2d3a6f5a3073988ac050c2d7b6655e2", GIT_DELTA_MODIFIED },
        { 0100644, "changed-in-master.txt", "ab6c44a2e84492ad4b41bb6bac87353e9d02ac8b", GIT_DELTA_UNMODIFIED },
        
        { 0100644, "conflicting.txt", "d427e0b2e138501a3d15cc376077a3631e15bd46", GIT_DELTA_UNMODIFIED },
        { 0100644, "conflicting.txt", "4e886e602529caa9ab11d71f86634bd1b6e0de10", GIT_DELTA_MODIFIED },
        { 0100644, "conflicting.txt", "2bd0a343aeef7a2cf0d158478966a6e587ff3863", GIT_DELTA_MODIFIED },
        
        { 0100644, "removed-in-branch.txt", "dfe3f22baa1f6fce5447901c3086bae368de6bdd", GIT_DELTA_UNMODIFIED },
        { 0100644, "removed-in-branch.txt", "dfe3f22baa1f6fce5447901c3086bae368de6bdd", GIT_DELTA_UNMODIFIED },
        { 0, "", "", GIT_DELTA_DELETED },
        
        { 0100644, "removed-in-master.txt", "5c3b68a71fc4fa5d362fd3875e53137c6a5ab7a5", GIT_DELTA_UNMODIFIED },
        { 0, "", "", GIT_DELTA_DELETED },
        { 0100644, "removed-in-master.txt", "5c3b68a71fc4fa5d362fd3875e53137c6a5ab7a5", GIT_DELTA_UNMODIFIED },
    };
    
    cl_assert(diff_tree = threeway(TREE_OID_ANCESTOR, TREE_OID_MASTER, TREE_OID_BRANCH, treediff_file_data, 7));
    
    git_diff_tree_list_free(diff_tree);
}

/*
 * TODO: enable this when strict diff computation is enabled
 *
void test_treediff_threeway__strict_renames(void)
{
    git_diff_tree_list *diff_tree;
    
    struct treediff_file_data treediff_file_data[] = {
        { 0, "", "", GIT_DELTA_UNMODIFIED },
        { 0100644, "added-in-master.txt", "233c0919c998ed110a4b6ff36f353aec8b713487", GIT_DELTA_ADDED },
        { 0, "", "", GIT_DELTA_UNMODIFIED },
        
        { 0100644, "automergeable.txt", "6212c31dab5e482247d7977e4f0dd3601decf13b", GIT_DELTA_UNMODIFIED },
        { 0100644, "automergeable.txt", "ee3fa1b8c00aff7fe02065fdb50864bb0d932ccf", GIT_DELTA_MODIFIED },
        { 0100644, "automergeable.txt", "6212c31dab5e482247d7977e4f0dd3601decf13b", GIT_DELTA_UNMODIFIED },
        
        { 0100644, "changed-in-master.txt", "ab6c44a2e84492ad4b41bb6bac87353e9d02ac8b", GIT_DELTA_UNMODIFIED },
        { 0100644, "changed-in-master.txt", "11deab00b2d3a6f5a3073988ac050c2d7b6655e2", GIT_DELTA_MODIFIED },
        { 0100644, "changed-in-master.txt", "ab6c44a2e84492ad4b41bb6bac87353e9d02ac8b", GIT_DELTA_UNMODIFIED },
        
        { 0100644, "conflicting.txt", "d427e0b2e138501a3d15cc376077a3631e15bd46", GIT_DELTA_UNMODIFIED },
        { 0100644, "conflicting.txt", "4e886e602529caa9ab11d71f86634bd1b6e0de10", GIT_DELTA_MODIFIED },
        { 0100644, "conflicting.txt", "d427e0b2e138501a3d15cc376077a3631e15bd46", GIT_DELTA_UNMODIFIED },
        
        { 0100644, "removed-in-branch.txt", "dfe3f22baa1f6fce5447901c3086bae368de6bdd", GIT_DELTA_UNMODIFIED },
        { 0100644, "removed-in-branch.txt", "dfe3f22baa1f6fce5447901c3086bae368de6bdd", GIT_DELTA_UNMODIFIED },
        { 0100644, "renamed-in-branch.txt", "dfe3f22baa1f6fce5447901c3086bae368de6bdd", GIT_DELTA_RENAMED },
        
        { 0100644, "removed-in-master.txt", "5c3b68a71fc4fa5d362fd3875e53137c6a5ab7a5", GIT_DELTA_UNMODIFIED },
        { 0, "", "", GIT_DELTA_DELETED },
        { 0100644, "removed-in-master.txt", "5c3b68a71fc4fa5d362fd3875e53137c6a5ab7a5", GIT_DELTA_UNMODIFIED },
        
        { 0, "", "", GIT_DELTA_UNMODIFIED },
        { 0, "", "", GIT_DELTA_UNMODIFIED },
        { 0100644, "renamed.txt", "c8f06f2e3bb2964174677e91f0abead0e43c9e5d", GIT_DELTA_ADDED },

        { 0100644, "unchanged.txt", "c8f06f2e3bb2964174677e91f0abead0e43c9e5d", GIT_DELTA_UNMODIFIED },
        { 0100644, "unchanged.txt", "c8f06f2e3bb2964174677e91f0abead0e43c9e5d", GIT_DELTA_UNMODIFIED },
        { 0100644, "copied.txt", "c8f06f2e3bb2964174677e91f0abead0e43c9e5d", GIT_DELTA_RENAMED }
    };
    
    cl_assert(diff_tree = threeway(TREE_OID_ANCESTOR, TREE_OID_MASTER, TREE_OID_RENAMES1, treediff_file_data, 8));
    
    git_diff_tree_list_free(diff_tree);
}
*/

/*
 * TODO: enable this when diff computation is implemented.
 *
void test_treediff_threeway__best_renames(void)
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
