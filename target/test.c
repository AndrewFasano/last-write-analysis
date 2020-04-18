#include <unistd.h>
#include <stdio.h>

int main(void) {
  char *argv[] = { "/bin/ls", "-la", 0};
  char *envp[] =
  {
    "HOME=/"
  };
  execve(argv[0], &argv[0], envp);
  return -1;
}

