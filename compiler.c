#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/stat.h>

/* This compiler converts the link command that produces a libFuzzer binary to
	the command that produces a AFL++ custom mutator shared library,
	which uses the `LLVMFuzzerCustomMutator` and `LLVMFuzzerCustomCrossOver`. */

bool is_fsanitize_fuzzer(const char* s)
{
	if (strncmp(s, "-fsanitize=", strlen("-fsanitize=")) != 0)
		return false;
	char* buf = strdup(s + strlen("-fsanitize="));
	char* p = buf; char* next;
	while ((next = strchr(p, ',')) != NULL)
	{
		*next = 0;
		if (strcmp(p, "fuzzer") == 0)
		{
			free(buf);
			return true;
		}
		p = next + 1;
	}
	bool ret = strcmp(p, "fuzzer") == 0;
	free(buf);
	return ret;
}

bool is_libfuzzer_link(int argc, char const *argv[])
{
	for (int i = 0; i < argc; ++i)
	{
		// If command is not link command.
		if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "-E") == 0)
			return false;
	}
	for (int i = 0; i < argc; ++i)
	{
		// If contains `-fsanitize=fuzzer`, it is considered as extraction target.
		if (is_fsanitize_fuzzer(argv[i]))
			return true;
	}
	return false;
}

const char* find_repo_path(const char* argv0)
{
	const char* lib_path = getenv("LIBFUZZER2AFL_PATH");
	if (lib_path)
	{
		if (access(lib_path, R_OK))
		{
			fprintf(stderr, "Invalid extractor library path\n");
			abort();
		}
		return lib_path;
	}

	if (access(LIBFUZZER2AFL_PATH"/afl.o", R_OK) == 0)
	{
		return LIBFUZZER2AFL_PATH;
	}

	const char* slash = strrchr(argv0, '/');
	if (slash)
	{
		char* dir = strdup(argv0);
		*strrchr(dir, '/') = 0;

		char* path;
		int r = asprintf(&path, "%s/afl.o", dir);
		if (r < 0) abort();
		if (!access(path, R_OK)) return dir;

		free(path); free(dir);
	}

	fprintf(stderr, "TODO\n");
	abort();
}

int main(int argc, char const *argv[])
{
	if (argc <= 1)
	{
		puts("LibFuzzer2AFL Compiler by Mem2019");
		return 0;
	}

	char const** new_argv = (char const**)malloc((argc + 100) * sizeof(char const*));
	int new_argc = 0;

	if (strstr(argv[0], "++") == NULL)
	{
		const char* cc = getenv("EXT_CC");
		new_argv[new_argc++] = cc ? cc : "clang";
	}
	else
	{
		const char* cxx = getenv("EXT_CXX");
		new_argv[new_argc++] = cxx ? cxx : "clang++";
	}

	bool if_libfuzzer = is_libfuzzer_link(argc, argv);

	if (if_libfuzzer)
	{
		new_argv[new_argc++] = "-shared";
		new_argv[new_argc++] = "-fPIC";
		new_argv[new_argc++] = "-Wl,--no-undefined";
	}

	for (int i = 1; i < argc; ++i)
	{
		if (strncmp(argv[i], "-fsanitize=", strlen("-fsanitize=")) == 0)
			continue;
		new_argv[new_argc++] = argv[i];
	}

	if (if_libfuzzer)
	{
		char* path;
		const char* repo_path = find_repo_path(argv[0]);
		int r = asprintf(&path, "%s/afl.o", repo_path);
		if (r < 0) abort();
		new_argv[new_argc++] = path;
		path = NULL;
		r = asprintf(&path, "%s/libfuzzer-mutator.a", repo_path);
		if (r < 0) abort();
		new_argv[new_argc++] = path;
		new_argv[new_argc++] = "-lstdc++";
		new_argv[new_argc++] = "-lm";
	}
	new_argv[new_argc++] = "-Wno-unused-command-line-argument";
	new_argv[new_argc] = NULL;

	if (getenv("SHOW_COMPILER_ARGS"))
	{
		for (int i = 0; i < argc; ++i)
			fprintf(stderr, "%s ", argv[i]);
		fprintf(stderr, "\n");
		for (const char** i = new_argv; *i; ++i)
			fprintf(stderr, "%s ", *i);
		fprintf(stderr, "\n");
	}

	execvp(new_argv[0], (char**)new_argv);
	abort();
	return 0;
}