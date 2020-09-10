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
#include <libgen.h>
#include <string.h>


/*
=====================================================================

distorm included as disassembler

=======================================================================
*/
#include "include/distorm.h"
#define MAX_INSTRUCTIONS (1000)

int counter = 0;
/*
int load_file(char* file_address)
{
        /* load and prepare binary file to be debuggued
                - 64 / 32 bit class file
                - machine file x86_x64
                - Little endian / Big endian
                - OS ABI
                - fork and ptrace
        

}
*/

void splash()
{
        puts("\n===============================================================\n");
        puts(" ___                 ___                   ___               ");
        puts("(   )               (   )                 (   )              ");
        puts("| | .-.     .--.    | |   ___     .---.   | |_       .--.   ");
        puts("| |/   \\   /    \\   | |  (   )   / .-, \\ (   __)    /    \\  ");
        puts("|  .-. .  |  .-. ;  | |  ' /    (__) ; |  | |      |  .-. ; ");
        puts("| |  | |  |  | | |  | |,' /       .'`  |  | | ___  |  | | | ");
        puts("| |  | |  |  |/  |  | .  '.      / .'| |  | |(   ) |  |/  | ");
        puts("| |  | |  |  ' _.'  | | `. \\    | /  | |  | | | |  |  ' _.' ");
        puts("| |  | |  |  .'.-.  | |   \\ \\   ; |  ; |  | ' | |  |  .'.-. ");
        puts("| |  | |  '  `-' /  | |    \\ .  ' `-'  |  ' `-' ;  '  `-' / ");
        puts("(___)(___)  `.__.'  (___ ) (___) `.__.'_.   `.__.    `.__.'  ");
        puts("\n===============================================================\n");
        printf("\nHecate dispell some of the anti-disassembling, anti-debugging and also anti-vm tricks.\nFind any data pattern and code pattern that program can create and use in the execution time.\n");

}

int main(int argc, char* argv[])
{
        //splash();
        pid_t child;
        _DecodedInst decodedInstructions[15];
        _DecodeType dt = Decode32Bits;
        unsigned int decodedInstructionsCount = 0;
        //Instruction buffer opcode
        unsigned char* opcode_buf = (unsigned char*) calloc(1, 15);
        char *program_pathname = argv[1];
        child = fork();
        if(child == 0)
        {
                ptrace(PTRACE_TRACEME, 0, NULL, NULL);
                execvp(program_pathname, ++argv);
                exit(0);
        }
        else
        {
                getchar();
                int status;
                unsigned long long ins = 0;
		bool check_callfunc = false;
                struct user_regs_struct regs;
                unsigned char prim;
                unsigned char *ptr_opcode;
                unsigned int opcode_size = 0;
                while (1)
                {
                        ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);
                        wait(&status);
                        if (WIFEXITED(status))
                                break;
                        ptrace(PTRACE_GETREGS, child, NULL, &regs);
                        printf("RIP: 0x%llx\n", regs.rip);
                        ins = ptrace(PTRACE_PEEKTEXT, child, regs.rip, NULL);
                        ptr_opcode = (unsigned char*)&ins;
                        printf("\ninstruction is :%016llX\n", ins);
                        for (opcode_size = 0 ; opcode_size < 15; opcode_size++)
                        {        
                                opcode_buf[opcode_size] = ptr_opcode[opcode_size];       
                        }

                        // here we got the instruction binary representation and needed to be disassembled using distorm
                        distorm_decode(0, (const unsigned char*)opcode_buf, opcode_size, dt, decodedInstructions, MAX_INSTRUCTIONS, &decodedInstructionsCount);
                        
                        //for (i = 0; i < decodedInstructionsCount; i++)
                        printf("%08lx (%02d) %-24s %s%s%s\r\n", decodedInstructions[0].offset, decodedInstructions[0].size, (char*)decodedInstructions[0].instructionHex.p, (char*)decodedInstructions[0].mnemonic.p, decodedInstructions[0].operands.length != 0 ? " " : "", (char*)decodedInstructions[0].operands.p);
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
			
                }
        }
        printf("[+] counter = %d", counter);
        return 0;
}
