// SPDX-License-Identifier: GPL-2.0
#include <test_progs.h>

static void toggle_object_autoload_progs(const struct bpf_object *obj,
					 const char *name_load)
{
	struct bpf_program *prog;

	bpf_object__for_each_program(prog, obj) {
		const char *name = bpf_program__name(prog);

		if (!strcmp(name_load, name))
			bpf_program__set_autoload(prog, true);
		else
			bpf_program__set_autoload(prog, false);
	}
}

void test_reference_tracking(void)
{
	const char *file = "test_sk_lookup_kern.o";
	const char *obj_name = "ref_track";
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, open_opts,
		.object_name = obj_name,
		.relaxed_maps = true,
	);
	struct bpf_object *obj_iter, *obj = NULL;
	struct bpf_program *prog;
	__u32 duration = 0;
	int err = 0;

	obj_iter = bpf_object__open_file(file, &open_opts);
	if (!ASSERT_OK_PTR(obj_iter, "obj_iter_open_file"))
		return;

	if (CHECK(strcmp(bpf_object__name(obj_iter), obj_name), "obj_name",
		  "wrong obj name '%s', expected '%s'\n",
		  bpf_object__name(obj_iter), obj_name))
		goto cleanup;

	bpf_object__for_each_program(prog, obj_iter) {
		const char *name;

		name = bpf_program__name(prog);
		if (!test__start_subtest(name))
			continue;

		obj = bpf_object__open_file(file, &open_opts);
		if (!ASSERT_OK_PTR(obj, "obj_open_file"))
			goto cleanup;

		toggle_object_autoload_progs(obj, name);
		/* Expect verifier failure if test name has 'err' */
		if (strncmp(name, "err_", sizeof("err_") - 1) == 0) {
			libbpf_print_fn_t old_print_fn;

			old_print_fn = libbpf_set_print(NULL);
			err = !bpf_object__load(obj);
			libbpf_set_print(old_print_fn);
		} else {
			err = bpf_object__load(obj);
		}
		ASSERT_OK(err, name);

		bpf_object__close(obj);
		obj = NULL;
	}

cleanup:
	bpf_object__close(obj);
	bpf_object__close(obj_iter);
}
