#!/bin/sh

test_description='Test reffiles backend consistency check'

GIT_TEST_DEFAULT_INITIAL_BRANCH_NAME=main
export GIT_TEST_DEFAULT_INITIAL_BRANCH_NAME
GIT_TEST_DEFAULT_REF_FORMAT=files
export GIT_TEST_DEFAULT_REF_FORMAT
TEST_PASSES_SANITIZE_LEAK=true

. ./test-lib.sh

test_expect_success 'ref name should be checked' '
	test_when_finished "rm -rf repo" &&
	git init repo &&
	branch_dir_prefix=.git/refs/heads &&
	tag_dir_prefix=.git/refs/tags &&
	cd repo &&

	git commit --allow-empty -m initial &&
	git checkout -b branch-1 &&
	git tag tag-1 &&
	git commit --allow-empty -m second &&
	git checkout -b branch-2 &&
	git tag tag-2 &&
	git tag multi_hierarchy/tag-2 &&

	cp $branch_dir_prefix/branch-1 $branch_dir_prefix/.branch-1 &&
	test_must_fail git refs verify 2>err &&
	cat >expect <<-EOF &&
	error: refs/heads/.branch-1: badRefName: invalid refname format
	EOF
	rm $branch_dir_prefix/.branch-1 &&
	test_cmp expect err &&

	cp $branch_dir_prefix/branch-1 $branch_dir_prefix/@ &&
	test_must_fail git refs verify 2>err &&
	cat >expect <<-EOF &&
	error: refs/heads/@: badRefName: invalid refname format
	EOF
	rm $branch_dir_prefix/@ &&
	test_cmp expect err &&

	cp $tag_dir_prefix/multi_hierarchy/tag-2 $tag_dir_prefix/multi_hierarchy/@ &&
	test_must_fail git refs verify 2>err &&
	cat >expect <<-EOF &&
	error: refs/tags/multi_hierarchy/@: badRefName: invalid refname format
	EOF
	rm $tag_dir_prefix/multi_hierarchy/@ &&
	test_cmp expect err &&

	cp $tag_dir_prefix/tag-1 $tag_dir_prefix/tag-1.lock &&
	git refs verify 2>err &&
	rm $tag_dir_prefix/tag-1.lock &&
	test_must_be_empty err &&

	cp $tag_dir_prefix/tag-1 $tag_dir_prefix/.lock &&
	test_must_fail git refs verify 2>err &&
	cat >expect <<-EOF &&
	error: refs/tags/.lock: badRefName: invalid refname format
	EOF
	rm $tag_dir_prefix/.lock &&
	test_cmp expect err
'

test_expect_success 'ref name check should be adapted into fsck messages' '
	test_when_finished "rm -rf repo" &&
	git init repo &&
	branch_dir_prefix=.git/refs/heads &&
	tag_dir_prefix=.git/refs/tags &&
	cd repo &&
	git commit --allow-empty -m initial &&
	git checkout -b branch-1 &&
	git tag tag-1 &&
	git commit --allow-empty -m second &&
	git checkout -b branch-2 &&
	git tag tag-2 &&

	cp $branch_dir_prefix/branch-1 $branch_dir_prefix/.branch-1 &&
	git -c fsck.badRefName=warn refs verify 2>err &&
	cat >expect <<-EOF &&
	warning: refs/heads/.branch-1: badRefName: invalid refname format
	EOF
	rm $branch_dir_prefix/.branch-1 &&
	test_cmp expect err &&

	cp $branch_dir_prefix/branch-1 $branch_dir_prefix/@ &&
	git -c fsck.badRefName=ignore refs verify 2>err &&
	test_must_be_empty err
'

test_expect_success 'regular ref content should be checked (individual)' '
	test_when_finished "rm -rf repo" &&
	git init repo &&
	branch_dir_prefix=.git/refs/heads &&
	tag_dir_prefix=.git/refs/tags &&
	cd repo &&
	test_commit default &&
	mkdir -p "$branch_dir_prefix/a/b" &&

	git refs verify 2>err &&
	test_must_be_empty err &&

	printf "%s" "$(git rev-parse main)" >$branch_dir_prefix/branch-no-newline &&
	git refs verify 2>err &&
	cat >expect <<-EOF &&
	warning: refs/heads/branch-no-newline: refMissingNewline: missing newline
	EOF
	rm $branch_dir_prefix/branch-no-newline &&
	test_cmp expect err &&

	printf "%s garbage" "$(git rev-parse main)" >$branch_dir_prefix/branch-garbage &&
	git refs verify 2>err &&
	cat >expect <<-EOF &&
	warning: refs/heads/branch-garbage: trailingRefContent: trailing garbage in ref
	EOF
	rm $branch_dir_prefix/branch-garbage &&
	test_cmp expect err &&

	printf "%s\n\n\n" "$(git rev-parse main)" >$tag_dir_prefix/tag-garbage-1 &&
	git refs verify 2>err &&
	cat >expect <<-EOF &&
	warning: refs/tags/tag-garbage-1: trailingRefContent: trailing garbage in ref
	EOF
	rm $tag_dir_prefix/tag-garbage-1 &&
	test_cmp expect err &&

	printf "%s\n\n\n  garbage" "$(git rev-parse main)" >$tag_dir_prefix/tag-garbage-2 &&
	git refs verify 2>err &&
	cat >expect <<-EOF &&
	warning: refs/tags/tag-garbage-2: trailingRefContent: trailing garbage in ref
	EOF
	rm $tag_dir_prefix/tag-garbage-2 &&
	test_cmp expect err &&

	printf "%s    garbage\n\na" "$(git rev-parse main)" >$tag_dir_prefix/tag-garbage-3 &&
	git refs verify 2>err &&
	cat >expect <<-EOF &&
	warning: refs/tags/tag-garbage-3: trailingRefContent: trailing garbage in ref
	EOF
	rm $tag_dir_prefix/tag-garbage-3 &&
	test_cmp expect err &&

	printf "%s garbage" "$(git rev-parse main)" >$tag_dir_prefix/tag-garbage-4 &&
	test_must_fail git -c fsck.trailingRefContent=error refs verify 2>err &&
	cat >expect <<-EOF &&
	error: refs/tags/tag-garbage-4: trailingRefContent: trailing garbage in ref
	EOF
	rm $tag_dir_prefix/tag-garbage-4 &&
	test_cmp expect err &&

	printf "%sx" "$(git rev-parse main)" >$tag_dir_prefix/tag-bad-1 &&
	test_must_fail git refs verify 2>err &&
	cat >expect <<-EOF &&
	error: refs/tags/tag-bad-1: badRefContent: invalid ref content
	EOF
	rm $tag_dir_prefix/tag-bad-1 &&
	test_cmp expect err &&

	printf "xfsazqfxcadas" >$tag_dir_prefix/tag-bad-2 &&
	test_must_fail git refs verify 2>err &&
	cat >expect <<-EOF &&
	error: refs/tags/tag-bad-2: badRefContent: invalid ref content
	EOF
	rm $tag_dir_prefix/tag-bad-2 &&
	test_cmp expect err &&

	printf "xfsazqfxcadas" >$branch_dir_prefix/a/b/branch-bad &&
	test_must_fail git refs verify 2>err &&
	cat >expect <<-EOF &&
	error: refs/heads/a/b/branch-bad: badRefContent: invalid ref content
	EOF
	rm $branch_dir_prefix/a/b/branch-bad &&
	test_cmp expect err
'

test_expect_success 'regular ref content should be checked (aggregate)' '
	test_when_finished "rm -rf repo" &&
	git init repo &&
	branch_dir_prefix=.git/refs/heads &&
	tag_dir_prefix=.git/refs/tags &&
	cd repo &&
	test_commit default &&
	mkdir -p "$branch_dir_prefix/a/b" &&

	printf "%s" "$(git rev-parse main)" >$branch_dir_prefix/branch-no-newline &&
	printf "%s garbage" "$(git rev-parse main)" >$branch_dir_prefix/branch-garbage &&
	printf "%s\n\n\n" "$(git rev-parse main)" >$tag_dir_prefix/tag-garbage-1 &&
	printf "%s\n\n\n  garbage" "$(git rev-parse main)" >$tag_dir_prefix/tag-garbage-2 &&
	printf "%s    garbage\n\na" "$(git rev-parse main)" >$tag_dir_prefix/tag-garbage-3 &&
	printf "%s garbage" "$(git rev-parse main)" >$tag_dir_prefix/tag-garbage-4 &&
	printf "%sx" "$(git rev-parse main)" >$tag_dir_prefix/tag-bad-1 &&
	printf "xfsazqfxcadas" >$tag_dir_prefix/tag-bad-2 &&
	printf "xfsazqfxcadas" >$branch_dir_prefix/a/b/branch-bad &&

	test_must_fail git refs verify 2>err &&
	cat >expect <<-EOF &&
	error: refs/heads/a/b/branch-bad: badRefContent: invalid ref content
	error: refs/tags/tag-bad-1: badRefContent: invalid ref content
	error: refs/tags/tag-bad-2: badRefContent: invalid ref content
	warning: refs/heads/branch-garbage: trailingRefContent: trailing garbage in ref
	warning: refs/heads/branch-no-newline: refMissingNewline: missing newline
	warning: refs/tags/tag-garbage-1: trailingRefContent: trailing garbage in ref
	warning: refs/tags/tag-garbage-2: trailingRefContent: trailing garbage in ref
	warning: refs/tags/tag-garbage-3: trailingRefContent: trailing garbage in ref
	warning: refs/tags/tag-garbage-4: trailingRefContent: trailing garbage in ref
	EOF
	sort err >sorted_err &&
	test_cmp expect sorted_err
'

test_done
