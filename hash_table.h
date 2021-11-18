#ifndef __HASH_TABLE_H__
#define __HASH_TABLE_H__
#include <stdint.h>

struct nlist { /* table entry: */
    struct nlist *next; /* next entry in chain */
    char *name; /* defined name */
    uint8_t *defn; /* replacement text */
    uint8_t key;
};

unsigned hash(char *s);
struct nlist *lookup(char *s);
struct nlist *install(char *name, uint8_t *defn, uint8_t key);
#endif