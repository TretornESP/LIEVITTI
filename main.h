#ifndef __MAIN_H__
#define __MAIN_H__
#include <stdint.h>
#include <signal.h>

typedef struct {
    int start;
    int end;
} SECTION;

extern uint8_t shellcode[];
extern int shellcode_size;

int get_epoint(uint8_t* buffer);
static void dbg_trap(int signo);
void get_section(uint8_t* buffer, int section, SECTION* s);
int count_sections(uint8_t* buffer);
void encrypt(uint8_t* buffer, uint8_t key);
void encrypt_section(uint8_t* buffer, SECTION s, uint8_t key);
void decrypt(uint8_t* buffer, uint8_t key);
void decrypt_section(uint8_t* buffer, SECTION s, uint8_t key);
int check_valid(uint8_t* buffer);
void dump_section(uint8_t* buffer, SECTION s);
uint8_t* init_experimental(uint8_t* buffer, void (*handler)(int), void (*sig)(int, siginfo_t*, void*), char* name, uint8_t key);
uint8_t* init(uint8_t* buffer, void (*handler)(int), char* name, uint8_t key);
void print_info(uint8_t* ptr);
void trap_step_special(const char* name);
void sig_step_special(const char* name, void* ucontext);
void dump(uint8_t* ptr);
void first_encrypt(uint8_t* ptr, uint8_t key);
#endif