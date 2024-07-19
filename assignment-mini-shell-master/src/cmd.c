// SPDX-License-Identifier: BSD-3-Clause

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/utsname.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "cmd.h"
#include "utils.h"

#define READ		0
#define WRITE		1

/**
 * Internal change-directory command.
 */
static bool shell_cd(word_t *dir)
{
	/* TODO: Execute cd. */
	if (dir == NULL)
		return false;
	int ret = chdir(dir->string);

	if (ret < 0)
		return false;
	return true;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	/* TODO: Execute exit/quit. */
	return SHELL_EXIT;
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	/* TODO: Sanity checks. */
	// fac verificarile initiale ca sa stiu daca comanda are formatul corect
	if (s == NULL || s->verb == NULL)
		return 1;
	// daca comanda este quit sau exit ies din shell
	if (!strcmp(s->verb->string, "exit") || !strcmp(s->verb->string, "quit"))
		return shell_exit();

	// aici verific daca este atribuita vreo valoare unei variabile de mediu
	// daca da atunci ii atribui valoarea verificand daca valoarea care este atribuita
	// contine si ea alte variabile de mediu
	// in final returnez ceva (0 sau 1) si trec la urmatoarea comanda
	if (s->verb && s->verb->next_part && !strcmp(s->verb->next_part->string, "=")) {
		word_t *p = s->verb->next_part->next_part;
		char *str = get_word(p);
		int ret = setenv(s->verb->string, str, 1);

		free(str);
		if (ret < 0)
			return 1;
		return 0;
	}

	// acum verific daca comanda data poate fi executata
	// am considerat ca o comanda poate fi executata daca se poate gasi
	// path-ul catre utilitarul corespunzator(de ex: pentru "ls" avem "/bin/ls")
	// verificarea ca verbul comenzii sa nu fie "cd" este deoarece pentru cd nu
	// se poate gasi path-ul
	char command[300];

	snprintf(command, sizeof(command), "which %s", s->verb->string);
	FILE *fc = popen(command, "r");
	char path[300];

	for (int i = 0; i < 300; ++i)
		path[i] = '\0';
	if (fc && !fgets(path, sizeof(path), fc) && strcmp(s->verb->string, "cd"))
		return 1;
	if (path[0] == '\0' && strcmp(s->verb->string, "cd"))
		return 1;
	fclose(fc);

	/* TODO: If builtin command, execute the command. */
	if (!strcmp(s->verb->string, "true"))
		return 0;
	if (!strcmp(s->verb->string, "false"))
		return 1;

	if (s->verb && !strcmp(s->verb->string, "cd") && !s->out && !s->in && !s->err) {
		if (shell_cd(s->params) == true)
			return 0;
		return 1;
	}

	/* TODO: If external command:
	 *   1. Fork new process
	 *     2c. Perform redirections in child
	 *     3c. Load executable in child
	 *   2. Wait for child
	 *   3. Return exit status
	 */
	//aici se creeaza procesul copil
	bool rc = true;
	pid_t pid = fork();

	if (!pid) {
		//salvez intai file descriptorii pentru stdin, stdout si stderr
		int fd_err;
		int fd_in;
		int fd_out;
		int fd_stdin = dup(0);
		int fd_stdout = dup(1);
		int fd_stderr = dup(2);

		// verific daca erorile sunt redirectate
		if (s->err) {
			if (s->io_flags == IO_ERR_APPEND)
				fd_err = open(s->err->string, O_WRONLY | O_CREAT | O_APPEND, 0644);
			else
				fd_err = open(s->err->string, O_WRONLY | O_CREAT, 0644);
			if (fd_err < 0)
				return 1;
			dup2(fd_err, 2);
		}
		// verifica daca intrarea este redirectata
		if (s->in) {
			fd_in = open(s->in->string, O_RDONLY | O_CREAT, 0644);
			if (fd_in < 0)
				return 1;
			dup2(fd_in, 0);
		}
		// verific daca iesirea este redirectata
		if (s->out) {
			char *strOut = get_word(s->out);

			if (s->io_flags == IO_OUT_APPEND || s->err)
				fd_out = open(strOut, O_WRONLY | O_CREAT | O_APPEND, 0644);
			else
				fd_out = open(strOut, O_WRONLY | O_CREAT | O_TRUNC, 0644);
			free(strOut);
			if (fd_out < 0)
				exit(1);
			dup2(fd_out, 1);
		}
		// consider cazul in care trebuie sa merg in alt director, dar intai a trebuit sa creez
		// un fisier in directorul curent
		if (s->verb && !strcmp(s->verb->string, "cd") && (s->out || s->in || s->err)) {
			int ret = 1;

			if (shell_cd(s->params) == true)
				ret = 0;
			if (s->err) {
				dup2(fd_stderr, 2);
				close(fd_err);
				close(fd_stderr);
			}
			if (s->in) {
				dup2(fd_stdin, 0);
				close(fd_in);
				close(fd_stderr);
			}
			if (s->out) {
				dup2(fd_stdout, 1);
				close(fd_out);
				close(fd_stdout);
			}
			exit(ret);
		}
		// execut comanda
		int i;
		char **argv = get_argv(s, &i);

		execvp(s->verb->string, argv);
		free(argv);
		//redirectez stdin, stdout si stderr unde erau initial
		if (s->err) {
			dup2(fd_stderr, 2);
			close(fd_err);
			close(fd_stderr);
		}
		if (s->in) {
			dup2(fd_stdin, 0);
			close(fd_in);
			close(fd_stderr);
		}
		if (s->out) {
			dup2(fd_stdout, 1);
			close(fd_out);
			close(fd_stdout);
		}
		if (rc == false)
			exit(1);
		exit(0);
	} else {
		// din parinte astept copilul
		int status;
		int wait_ret = waitpid(pid, &status, 0);

		if (wait_ret < 0)
			exit(1);
		if (s->verb && !strcmp(s->verb->string, "cd") && (s->out || s->in || s->err)) {
			s->in = NULL;
			s->out = NULL;
			s->err = NULL;
			return parse_simple(s, level, father);
		}
		return WEXITSTATUS(status);
	}
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level, command_t *father)
{
	/* TODO: Execute cmd1 and cmd2 simultaneously. */
	// creez 2 copii care vor executa comenzile din cmd1 si cmd2
	pid_t pid1 = fork();

	if (pid1 == 0) {
		int rc1 = parse_command(cmd1, level + 1, father);

		exit(rc1);
	}
	pid_t pid2 = fork();

	if (pid2 == 0) {
		int rc2 = parse_command(cmd2, level + 1, father);

		exit(rc2);
	}
	int status1, status2;

	// astept copiii
	waitpid(pid1, &status1, 0);
	waitpid(pid2, &status2, 0);
	return true; /* TODO: Replace with actual exit status. */
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2).
 */
static bool run_on_pipe(command_t *cmd1, command_t *cmd2, int level, command_t *father)
{
	/* TODO: Redirect the output of cmd1 to the input of cmd2. */
	if (cmd1 == NULL || cmd2 == NULL)
		return false;
	// consider cazurile pentru comenzi de tipul true/false
	if (cmd1->scmd && !strcmp(cmd1->scmd->verb->string, "true") &&
		cmd2->scmd && !strcmp(cmd2->scmd->verb->string, "true"))
		return true;
	if (cmd1->scmd && !strcmp(cmd1->scmd->verb->string, "true") &&
		cmd2->scmd && !strcmp(cmd2->scmd->verb->string, "false"))
		return false;
	if (cmd1->scmd && !strcmp(cmd1->scmd->verb->string, "false") &&
		cmd2->scmd && !strcmp(cmd2->scmd->verb->string, "true"))
		return true;
	if (cmd1->scmd && !strcmp(cmd1->scmd->verb->string, "false") &&
		cmd2->scmd && !strcmp(cmd2->scmd->verb->string, "false"))
		return false;
	// creez pipe-ul
	int pipedes[2];
	int rc = pipe(pipedes);

	if (rc < 0)
		return false;
	pid_t pid = fork();

	// parintele scrie si copilul citeste
	// de asemenea fiecare copil poate deveni si el parinte
	// prin apelul recursiv al functiei parse_command
	if (!pid) {
		int fd_stdin = dup(0);

		close(pipedes[WRITE]);
		dup2(pipedes[READ], 0);
		close(pipedes[READ]);
		int rc2 = parse_command(cmd2, level + 1, father);

		dup2(fd_stdin, 0);
		close(fd_stdin);
		exit(rc2);
	} else {
		int fd_stdout = dup(1);

		close(pipedes[READ]);
		dup2(pipedes[WRITE], 1);
		close(pipedes[WRITE]);
		int rc1 = parse_command(cmd1, level + 1, father);

		if (rc1)
			return false;
		dup2(fd_stdout, 1);
		close(fd_stdout);
		int status;
		int wait_ret = waitpid(pid, &status, 0);

		if (wait_ret < 0)
			return false;
		return true;
	}
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	/* TODO: sanity checks */
	if (c == NULL)
		return shell_exit();
	int rc = SHELL_EXIT;

	if (c->op == OP_NONE) {
		/* TODO: Execute a simple command. */
		rc = parse_simple(c->scmd, level, father);
		if (rc == shell_exit())
			return rc;
		if (rc) {
			printf("Execution failed for '%s'\n", c->scmd->verb->string);
			fflush(stdout);
			return 1;
		}
		return 0;
	}

	switch (c->op) {
	case OP_SEQUENTIAL:
		/* TODO: Execute the commands one after the other. */
		rc = parse_command(c->cmd1, level + 1, c);
		rc = parse_command(c->cmd2, level + 1, c);
		break;

	case OP_PARALLEL:
		/* TODO: Execute the commands simultaneously. */
		rc = 1;
		if (run_in_parallel(c->cmd1, c->cmd2, level + 1, c) == true)
			rc = 0;
		break;

	case OP_CONDITIONAL_NZERO:
		/* TODO: Execute the second command only if the first one
		 * returns non zero.
		 */
		rc = parse_command(c->cmd1, level + 1, c);
		if (rc)
			rc = parse_command(c->cmd2, level + 1, c);
		break;

	case OP_CONDITIONAL_ZERO:
		/* TODO: Execute the second command only if the first one
		 * returns zero.
		 */
		rc = parse_command(c->cmd1, level + 1, c);
		if (!rc)
			rc = parse_command(c->cmd2, level + 1, c);
		break;

	case OP_PIPE:
		/* TODO: Redirect the output of the first command to the
		 * input of the second.
		 */
		rc = 1;
		if (run_on_pipe(c->cmd1, c->cmd2, level + 1, c) == true)
			rc = 0;
		break;

	default:
		return shell_exit();
	}

	return rc; /* TODO: Replace with actual exit code of command. */
}
