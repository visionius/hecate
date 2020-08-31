#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>

int counter = 0;

int main(int argc, char** argv)
{
        pid_t child;

        child = fork();
        if(child == 0)
        {
                ptrace(PTRACE_TRACEME, 0, NULL, NULL);
                execl(argv[1], argv[2], NULL);
        }
        else
        {
                int status;
                unsigned ins;
		bool check_callfunc = false;
                struct user_regs_struct regs;
                unsigned char prim;
		unsigned int progcall;
                while (1)
                {
                        ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);
                        wait(&status);
                        if (WIFEXITED(status))
                                break;
                        ptrace(PTRACE_GETREGS, child, NULL, &regs);
                        ins = ptrace(PTRACE_PEEKTEXT, child, regs.rip, NULL);
                        prim = (unsigned)0xFF & ins;
                        if(check_callfunc)
                        {
                                //printf("[c] func called address: %p\n", regs.rip);
                                check_callfunc = false;
                        }
                        // Here in prim just mask for the first byte need to -m this cuz I need main functions!!
			/*
				[1] we need to find main function and nothing else!
				[2] 0x7ffff7fedec0 function call address like this is not for our program!!
				[3] function call with  its arguments could bring us better picture of program functionality
				[4] maby we should use another teq for finding function calls rather than fetch instructions and see the call opcodes
			*/
                        if (prim == 0xe8  || prim == 0xa9 || prim == 0xff)
                        {
                                check_callfunc = true;
                                counter++;
                        }
			printf("RIP: %p\n", regs.rip);
                }
        }
        printf("[+] counter = %d", counter);
        return 0;
}
