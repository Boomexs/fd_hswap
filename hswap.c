#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <fcntl.h>

static char syscall_breakpoint_assembly[] = "\x0f\x05\xcc"; // syscall 0f 05 and breakpoint cc (INT3)

void read_bytes(pid_t process, const uint32_t* address, uint32_t* bytes, int length) {
	int j = ((length + sizeof(uint32_t) -1) / sizeof(uint32_t));
	for (int i = 0; i < j; i++) {
		*bytes++ = ptrace(PTRACE_PEEKDATA, process, address++, NULL);
	}
}

void set_bytes(pid_t process, const uint32_t* address, const uint32_t* bytes, int length) {
	int j = ((length + sizeof(uint32_t) -1) / sizeof(uint32_t));
	for (int i = 0; i < j; i++) {
		ptrace(PTRACE_POKEDATA, process, address++, *bytes++);
	}
}

int swap_file_descriptors(pid_t pid, int file_descriptor, const char* outpath) {
	// attach ptrace
	ptrace(PTRACE_ATTACH, pid, NULL, NULL);
	waitpid(pid, NULL, 0);

	// Calculate the size of data to inject
	size_t size_of_data_to_inject = strlen(outpath) + 1 + sizeof(syscall_breakpoint_assembly);
	// add padding
	size_of_data_to_inject +=  size_of_data_to_inject % sizeof(uint32_t);
	size_t outpath_length = strlen(outpath)+1;

	// create a struct to hold
	struct user_regs_struct new_registers,original_registers;
	ptrace(PTRACE_GETREGS, pid, NULL, &new_registers);

	// Working address is the place where we are doing all of our syscalls (current instruction pointer)
	void* working_address = (void*)new_registers.rip;
	// Create a copy of the memory we will modify to restore it later
	void* original_memory = alloca(size_of_data_to_inject);
	read_bytes(pid, working_address, original_memory, size_of_data_to_inject);

	// Prepare a buffer to inject into the other program
	// create a buffer on the stack
	void* buffer_to_inject = alloca(size_of_data_to_inject);
	// init data with zeros
	memset(buffer_to_inject, 0, size_of_data_to_inject);
	// put the outpath string at the beggining of the buffer
	memcpy(buffer_to_inject, outpath, outpath_length);
	// after the outpath string put our syscall and breakpoint machine code
	memcpy(buffer_to_inject+outpath_length, syscall_breakpoint_assembly, sizeof(syscall_breakpoint_assembly));

	// Inject our code into the working address
	set_bytes(pid, working_address, buffer_to_inject, size_of_data_to_inject);

	// open syscall
	memcpy(&original_registers, &new_registers, sizeof(new_registers));
	new_registers.rip = (unsigned long long int)(working_address+outpath_length);
	new_registers.rax = 2;
	new_registers.rdi = (unsigned long long int)working_address;
	new_registers.rsi = O_RDWR | O_CREAT;
	new_registers.rdx = 0644;
	ptrace(PTRACE_SETREGS, pid, NULL, &new_registers);
	ptrace(PTRACE_CONT, pid, NULL, NULL);
	waitpid(pid, NULL, 0);

	// dup2 syscall
	ptrace(PTRACE_GETREGS, pid, NULL, &new_registers);
	new_registers.rip = (unsigned long long int)(working_address+outpath_length);
	new_registers.rdi = new_registers.rax;
	new_registers.rax = 33;
	new_registers.rsi = file_descriptor;
	ptrace(PTRACE_SETREGS, pid, NULL, &new_registers);
	ptrace(PTRACE_CONT, pid, NULL, NULL);
	waitpid(pid, NULL, 0);

	// close syscall
	ptrace(PTRACE_GETREGS, pid, NULL, &new_registers);
	new_registers.rip = (unsigned long long int)(working_address+outpath_length);
	new_registers.rax = 3;
	ptrace(PTRACE_SETREGS, pid, NULL, &new_registers);
	ptrace(PTRACE_CONT, pid, NULL, NULL);
	waitpid(pid, NULL, 0);

	// Return registers to normal
	ptrace(PTRACE_GETREGS, pid, NULL, &new_registers);
	set_bytes(pid, working_address, original_memory, size_of_data_to_inject);
	ptrace(PTRACE_SETREGS, pid, NULL, &original_registers);
	ptrace(PTRACE_DETACH, pid, NULL, NULL);

	return 0;
}

int main(int argc, char * argv[]) {
	if (argc != 4) {
		printf("Usage: %s <pid> <fd> <new outpath>\n", argv[0]);
		return 1;
	}
	int pid = strtol(argv[1], NULL, 10);
	int file_descriptor = strtol(argv[2], NULL, 10);
	swap_file_descriptors(pid, file_descriptor, argv[3]);
}
