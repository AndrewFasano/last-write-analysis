#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char** argv) {

  // Dynamically set fname
  char fname[32];
  if (argc == 1)
    strncpy(fname, "/etc/passwd", 32);
  else
    strncpy(fname, "/etc/hosts", 32);

  // Use fname to open a file
  FILE *f = fopen(fname, "r");
  if (f == NULL) {
    return 1;
  }
  char c;
  while ((c = fgetc(f)) != EOF) {
    printf("%c", c);
    if (c == '\n') break;
  }
  fclose(f);

  char *new_argv[] = { "/bin/ls", "-la", 0};
  char *new_envp[] =
  {
    "HOME=/"
  };
  execve(new_argv[0], &new_argv[0], new_envp);
  return -1;
}

