#include "hash_table.h"
#include <string.h>
#include <stdlib.h>

#define HASHSIZE 101
static struct nlist *hashtab[HASHSIZE]; /* pointer table */

unsigned hash(char *s)
{
    
    unsigned hashval;
    for (hashval = 0; *s != '\0'; s++)
      hashval = *s + 31 * hashval;
    return hashval % HASHSIZE;
}

struct nlist *lookup(char *s)
{
    struct nlist *np;
    for (np = hashtab[hash(s)]; np != 0; np = np->next)
        if (strcmp(s, np->name) == 0)
          return np; /* found */
    return 0; /* not found */
}

struct nlist *install(char *name, uint8_t *defn, uint8_t key)
{
    struct nlist *np;
    unsigned hashval;
    if ((np = lookup(name)) == 0) { /* not found */
        np = (struct nlist *) malloc(sizeof(*np));
        if (np == 0 || (np->name = strdup(name)) == 0)
          return 0;
        hashval = hash(name);
        np->next = hashtab[hashval];
        hashtab[hashval] = np;
    }
    np->defn = defn;
    np->key = key;
    return np;
}