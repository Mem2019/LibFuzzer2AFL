#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>

/* Call `execvp` in child process, return true if execution is successful. */
bool execvp_child(char* const* argv)
{
	pid_t pid = fork();

	if (pid < 0)
	{
		perror("fork");
		return false;
	}
	else if (pid == 0)
	{
		execvp(argv[0], argv);
		perror("execvp");
		abort();
	}
	else
	{
		int status;
		if (waitpid(pid, &status, 0) < 0)
			return false;
		return WIFEXITED(status) && WEXITSTATUS(status) == 0;
	}
}

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

/*
The function identifies libfuzzer linkage, returns non-zero if it is.
When flag `-fsanitize=fuzzer` is detected, it returns 2.
Since such flag is going to be removed, we need to link with `libfuzzer-mutator.a` for
symbol `LLVMFuzzerMutate`. When the binary is considered as libfuzzer binary,
but is generated with `-fsanitize=fuzzer-no-link`, we assume `LLVMFuzzerMutate` exists
in the binary so we do not link with `libfuzzer-mutator.a`.
*/

int is_libfuzzer_link(int argc, char const *argv[], const char* clang)
{
	for (int i = 0; i < argc; ++i)
	{
		// If command is not link command.
		if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "-E") == 0)
			return 0;
	}
	for (int i = 0; i < argc; ++i)
	{
		// If contains `-fsanitize=fuzzer`, it is considered as extraction target.
		if (is_fsanitize_fuzzer(argv[i]))
			return 2;
	}

	// Then we go to the slow path, we try to compile the binary,
	// and check if it contains LLVM fuzzing strings.
	char const** new_argv = (char const**)malloc((argc + 1) * sizeof(char const*));
	int new_argc = 0;
	new_argv[new_argc++] = clang;
	const char* file_name = NULL;
	for (int i = 1; i < argc; ++i)
	{
		if (strcmp(argv[i], "-s") != 0) // We don't strip.
			new_argv[new_argc++] = argv[i];
		if (strcmp(argv[i], "-o") == 0 && i + 1 < argc)
			file_name = argv[i + 1];
	}
	new_argv[new_argc] = NULL;
	if (!execvp_child((char**)new_argv))
		exit(EXIT_FAILURE);
	if (file_name == NULL)
		file_name = "a.out";

	int fd = open(file_name, O_RDONLY);
	if (fd < 0)
	{
		perror("open");
		exit(EXIT_FAILURE);
	}
	struct stat st;
	if (fstat(fd, &st) < 0)
	{
		perror("fstat");
		exit(EXIT_FAILURE);
	}

	void* file_content = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (file_content == MAP_FAILED)
	{
		perror("mmap");
		exit(EXIT_FAILURE);
	}

	// The binary is considered as libfuzzer if it contains string
	// `LLVMFuzzerTestOneInput` and contains one of
	// `LLVMFuzzerCustomMutator` or `LLVMFuzzerCustomCrossOver`.
	static const char toi[] = "LLVMFuzzerTestOneInput";
	static const char cm[] = "LLVMFuzzerCustomMutator";
	static const char cco[] = "LLVMFuzzerCustomCrossOver";
	int ret =
		memmem(file_content, st.st_size, toi, sizeof(toi)) != NULL &&
		(memmem(file_content, st.st_size, cm, sizeof(cm)) != NULL ||
			memmem(file_content, st.st_size, cco, sizeof(cco)) != NULL);

	if (munmap(file_content, st.st_size) < 0)
	{
		perror("munmap");
		exit(EXIT_FAILURE);
	}

	close(fd);

	return ret;
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

	int if_libfuzzer = is_libfuzzer_link(argc, argv, new_argv[0]);
	new_argv[new_argc++] = "-fPIC"; // always PIC

	if (if_libfuzzer)
	{
		new_argv[new_argc++] = "-shared";
		new_argv[new_argc++] = "-Wl,--no-undefined";
	}

	bool has_fsan = false;
	for (int i = 1; i < argc; ++i)
	{
		if (strncmp(argv[i], "-fsanitize=", strlen("-fsanitize=")) == 0)
		{
			has_fsan = true;
			continue;
		}
		if (strcmp(argv[i], "-fno-PIC") == 0 || strcmp(argv[i], "-fno-PIE") == 0 ||
			strcmp(argv[i], "-fno-pic") == 0 || strcmp(argv[i], "-fno-pie") == 0)
			continue;
		new_argv[new_argc++] = argv[i];
	}

	char* path; int r;
	const char* repo_path = find_repo_path(argv[0]);
	if (has_fsan)
	{ // If we have removed any `-fsanitize` flag,
		// we link with the dummy interface to prevent link error.
		r = asprintf(&path, "%s/common_interface_defs.o", repo_path);
		if (r < 0) abort();
		new_argv[new_argc++] = path;
	}
	if (if_libfuzzer)
	{
		r = asprintf(&path, "%s/afl.o", repo_path);
		if (r < 0) abort();
		new_argv[new_argc++] = path;
		if (if_libfuzzer == 2)
		{
			r = asprintf(&path, "%s/libfuzzer-mutator.a", repo_path);
			if (r < 0) abort();
			new_argv[new_argc++] = path;
			new_argv[new_argc++] = "-lstdc++";
			new_argv[new_argc++] = "-lm";
		}
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