#include <sys/mman.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <ucontext.h>

#include "main.h"
#include "hash_table.h"

#ifndef HARDCODED
# define MAX_SIZE 0x1000 //Largest assembly size available
#endif

#ifdef DEBUG
# define DEBUG_PRINT(x) printf x
#else
# define DEBUG_PRINT(x) do {} while (0)
#endif

#define trap_step() trap_step_special(__func__) //This is really cool
#define sig_step() sig_step_special(__func__, ucontext) //This is really cool

size_t bsize;
int current_section;

int get_epoint(uint8_t* buffer) {
    SECTION s;
    get_section(buffer, current_section, &s);
    return s.end;
}

void dbg_signal(int sig, siginfo_t *info, void *ucontext) {
    
    sig_step();
}

static void dbg_trap(int signo) {
    DEBUG_PRINT(("[!] Debug trap, section = %d\n", current_section));
    DEBUG_PRINT(("[!] Debug: My name is %s and my buffer is at: %p\n", __func__, lookup((char*)__func__)->defn));
    trap_step();

}

void get_section(uint8_t* buffer, int section, SECTION* s) {
    int start = 0;
    int end = 0;
    int csec = 0;
    for (int i = 1; i < bsize; i++) {
        if (buffer[i-1] == 0xcc) {
            start = end;
            end = i;
            //printf("[+]Section %d start: %d end: %d\n", csec, start, end);
            if (csec == section) {
                //printf("Match with start: %d section: %d\n", start, section);
                s->start = start;
                s->end = end;
                return;
            }
            csec++;
        }
    }
    if (s->end != 0) {
        s->start = end;
        s->end = bsize;
        //printf("[+]Last section %d start: %d end: %d\n", csec, end, (int)bsize);
    } else {
        s->start = -1;
        s->end = -1;
        printf("[-]No section found\n");
    }
}

int count_sections(uint8_t* buffer) {
    int csec = 1;
    for (int i = 0; i < bsize; i++) {
        if (buffer[i] == 0xcc) {
            csec++;
        }
    }
    DEBUG_PRINT(("[!]Buffer has %d sections\n", csec));
    return csec;
}

void encrypt(uint8_t* buffer, uint8_t key) {
    for (int i = 0; i < bsize; i++) {
        if (buffer[i] != 0xcc) {
            buffer[i] ^= key;
        }
    }
    DEBUG_PRINT(("[+]Buffer encrypted\n"));
}

void encrypt_section(uint8_t* buffer, SECTION s, uint8_t key) {
    for (int i = s.start; i < s.end; i++) {
        if (buffer[i] != 0xcc) {
            buffer[i] ^= key;
        }
    }
    DEBUG_PRINT(("[+]Buffer section encrypted from %d to %d\n", s.start, s.end));
}

void first_encrypt(uint8_t* buffer, uint8_t key) {
    int enc = 0;
    for (int i = 0; i < bsize; i++) {
        if (buffer[i] == 0xcc) {
            enc = 1;
        } else {
            if (enc) buffer[i] ^= key;
        }
    }
    DEBUG_PRINT(("[+]All but first sections encrypted!\n"));
}

//XOR Cyphering decryption == encrypting two times
void decrypt(uint8_t* buffer, uint8_t key) {
    encrypt(buffer, key);
}
void decrypt_section(uint8_t* buffer, SECTION s, uint8_t key) {
    encrypt_section(buffer, s, key);
}

int check_valid(uint8_t* buffer) {
    if (buffer == 0) {
        DEBUG_PRINT(("[-]Buffer is null\n"));
        return 0;
    }
    for (int i = 0; i < bsize; i++) {
        if (buffer[i] == 0xcc) {
            return 1;
        }
    }
    DEBUG_PRINT(("[-]Buffer doesnt contain breakpoints\n"));
    return 0;
}

void dump_section(uint8_t* buffer, SECTION s) {
    printf("[!]Section (%d:%d): ", s.start, s.end);
    for (int i = s.start; i < s.end; i++) {
        printf("\\x%02x", buffer[i]);
    }
    printf("\n");
}

void dump(uint8_t* buffer) {
    printf("[!]FULL DUMP: ");
    for (int i = 0; i < bsize; i++) {
        printf("\\x%02x", buffer[i]);
    }
    printf("\n");
}

//It is way easier to pass the name than to calculate name from pointer
uint8_t* init_experimental(uint8_t* buffer, void (*handler)(int), void (*sig)(int, siginfo_t*, void*), char* name, uint8_t key) {
    //Mmap is required for WSL2 as W^X overrides -z execstack option
    #ifndef HARDCODED
    uint8_t* ptr = mmap(0, MAX_SIZE,
                    PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    bsize = shellcode_size;
    #else
    uint8_t* ptr = mmap(0, sizeof(shellcode),
                    PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    bsize = sizeof(shellcode) -1;
    #endif
    memcpy(ptr, shellcode, bsize);
    current_section = 0;
    if (check_valid(ptr)) {
        printf("[+]Valid shellcode injected at %p\n", ptr);
    } else {
        printf("[-]Invalid shellcode or corrupted buffer\n");
        return 0;
    }
    if (handler && sig) {
        install(name, ptr, key);
        struct sigaction sa = {0};
        sa.sa_flags = SA_SIGINFO;
        sa.sa_sigaction = sig;
        signal(SIGTRAP, handler);
        sigaction(SIGSEGV, &sa, NULL);
        printf("[+]Handlers registered\n");
    } else {
        printf("[-]Shellcode was injected but one handler was invalid, aborting\n");
        return 0;
    }
    return ptr;
}

//It is way easier to pass the name than to calculate name from pointer
uint8_t* init(uint8_t* buffer, void (*handler)(int), char* name, uint8_t key) {
    //Mmap is required for WSL2 as W^X overrides -z execstack option
    #ifndef HARDCODED
    uint8_t* ptr = mmap(0, MAX_SIZE,
                    PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    bsize = shellcode_size;
    #else
    uint8_t* ptr = mmap(0, sizeof(shellcode),
                    PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    bsize = sizeof(shellcode) -1;
    #endif
    memcpy(ptr, shellcode, bsize);
    current_section = 0;
    if (check_valid(ptr)) {
        printf("[+]Valid shellcode injected at %p\n", ptr);
    } else {
        printf("[-]Invalid shellcode or corrupted buffer\n");
        return 0;
    }
    if (handler) {
        install(name, ptr, key);
        signal(SIGTRAP, handler);
        printf("[+]Handlers registered\n");
    } else {
        printf("[-]Shellcode was injected but one handler was invalid, aborting\n");
        return 0;
    }
    return ptr;
}

void decrypt_address(uint8_t *buffer, int address, uint8_t key) {

}

void print_info(uint8_t* ptr) {
    SECTION s;
    int sections = count_sections(ptr);
    for (int i = 0; i < sections; i++) {
        get_section(ptr, i, &s);
        printf("[+] Section %d: %d - %d\n", i, s.start, s.end);
        dump_section(ptr, s);
    }
}

void trap_step_special(const char* name) {
    int len = strlen(name)-strlen("_trap");
    char newstr[len];
    strncpy(newstr, name, len);
    newstr[len] = '\0';
    
    struct nlist * nl = lookup((char*)newstr);
    if (nl == 0) {
        printf("[-]Buffer not found for function %s\n", newstr);
        return;
    }
    uint8_t * buffer = nl->defn;
    uint8_t key = nl->key;

    SECTION cs, ns;
    get_section(buffer, current_section, &cs);
    DEBUG_PRINT(("[+]Stepping from section %d start: %d end: %d\n", current_section, cs.start, cs.end));
    current_section++;
    get_section(buffer, current_section, &ns);
    DEBUG_PRINT(("[+]Stepping to section %d start: %d end: %d\n", current_section, ns.start, ns.end));

    encrypt_section(buffer, cs, key);
    decrypt_section(buffer, ns, key);
}

void sig_step_special(const char* name, void* ctx) {
    int len = strlen(name)-strlen("_signal");
    char newstr[len];
    strncpy(newstr, name, len);
    newstr[len] = '\0';
    
    struct nlist * nl = lookup((char*)newstr);
    if (nl == 0) {
        printf("[-]Buffer not found for function %s\n", newstr);
        return;
    }
    uint8_t * buffer = nl->defn;
    uint8_t key = nl->key;

    printf("DECRYPTING\n");

    decrypt(buffer, key);
}

int main(void) {
    uint8_t* ptr = init(shellcode, dbg_trap, "dbg", 0x42); 
    first_encrypt(ptr, 0x42);
    ((void(*)())ptr)();
}
