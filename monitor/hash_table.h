#ifndef __HASH_TABLE__
#define __HASH_TABLE__

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <semaphore.h>
#include <stdint.h>

#ifndef	TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

/************************************************************************/
typedef  unsigned long  int  ub4;   /* unsigned 4-byte quantities */
typedef  unsigned       char ub1;

#define hashsize(n) ((ub4)1<<(n))
#define hashmask(n) (hashsize(n)-1)

static ub4 hash(register ub1 *k, register ub4 length, register ub4 level);

/*
	--------------------------------------------------------------------
	mix -- mix 4 32-bit values reversibly.
	Changing any input bit will usually change at least 32 output bits,
	whether the hash is run forward or in reverse.
	Changing any input bit will change each of the 32 output bits in d
	about half the time when inputs a,b,c,d are uniformly distributed.
	mix() takes 32 machine cycles.  No 16 or 24 cycle mixer works; this
	was confirmed by brute-force search.  This hash is the best of
	about 500,000 32-cycle hashes examined.
	--------------------------------------------------------------------
*/

#define mix(a,b,c,d) \
{ \
	a += d; d += a; a ^= (a>>7);  \
	b += a; a += b; b ^= (b<<13);  \
	c += b; b += c; c ^= (c>>17); \
	d += c; c += d; d ^= (d<<9); \
	a += d; d += a; a ^= (a>>3);  \
	b += a; a += b; b ^= (b<<7);  \
	c += b; b += c; c ^= (c>>15); \
	d += c; c += d; d ^= (d<<11); \
}

/*
	--------------------------------------------------------------------
	hash() -- hash a variable-length key into a 32-bit value
	k     : the key (the unaligned variable-length array of bytes)
	len   : the length of the key, counting by bytes
	level : can be any 4-byte value
	Returns a 32-bit value.  Every bit of the key affects every bit of
	the return value.  There are no funnels smaller than 32 bits.
	About 34+5len instructions.

	There is no need to divide by a prime (division is sooo slow!).  If
	you need less than 32 bits, use a bitmask.  For example, if you need
	only 10 bits, do
	h = (h & hashmask(10));
	In which case, the hash table should have hashsize(10) elements.

	If you are hashing n strings (ub1 **)k, do it like this:
	for (i=0, h=0; i<n; ++i) h = hash( k[i], len[i], h);

	(c) Bob Jenkins, 1996.  74512.261@compuserve.com.  You may use this
	code any way you wish, private, educational, or commercial, as long
	as this whole comment accompanies it.

	See http://ourworld.compuserve.com/homepages/bob_jenkins/evahash.htm
	Use for hash table lookup, or anything where one collision in 2^32 is
	acceptable.  Do NOT use for cryptographic purposes.
	--------------------------------------------------------------------
*/

static inline ub4 hash(register ub1 *k, register ub4 length, register ub4 level)
{
	register ub4 a,b,c,d,len;

	/* Set up the internal state */
	len = length;
	a = b = c = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
	d = level;               /* the previous hash value */

	/*---------------------------------------- handle most of the key */
	while (len >= 16)
	{
		a += (k[0] +((ub4)k[1]<<8) +((ub4)k[2]<<16) +((ub4)k[3]<<24));
		b += (k[4] +((ub4)k[5]<<8) +((ub4)k[6]<<16) +((ub4)k[7]<<24));
		c += (k[8] +((ub4)k[9]<<8) +((ub4)k[10]<<16)+((ub4)k[11]<<24));
		d += (k[12]+((ub4)k[13]<<8)+((ub4)k[14]<<16)+((ub4)k[15]<<24));
		mix(a,b,c,d);
		k += 16; len -= 16;
	}

	/*------------------------------------- handle the last 15 bytes */
	d += length;
	switch(len)              /* all the case statements fall through */
	{
		case 15: d+=((ub4)k[14]<<24);
		case 14: d+=((ub4)k[13]<<16);
		case 13: d+=((ub4)k[12]<<8);
			 /* the first byte of d is reserved for the length */
		case 12: c+=((ub4)k[11]<<24);
		case 11: c+=((ub4)k[10]<<16);
		case 10: c+=((ub4)k[9]<<8);
		case 9 : c+=k[8];
		case 8 : b+=((ub4)k[7]<<24);
		case 7 : b+=((ub4)k[6]<<16);
		case 6 : b+=((ub4)k[5]<<8);
		case 5 : b+=k[4];
		case 4 : a+=((ub4)k[3]<<24);
		case 3 : a+=((ub4)k[2]<<16);
		case 2 : a+=((ub4)k[1]<<8);
		case 1 : a+=k[0];
			 /* case 0: nothing left to add */
	}
	mix(a,b,c,d);
	/*-------------------------------------------- report the result */
	return d;
}

/************************************************************************/


typedef struct hash_entry_type
{
	void *key;
	void *data;
	uint32_t key_len;
	struct hash_entry_type *next;
	struct hash_entry_type *prev;
} hash_entry_t;

typedef struct
{
	hash_entry_t **row;
	hash_entry_t **tail;
#ifdef __USE_HASH_LOCKS__
	sem_t *row_lock;
#endif
	uint32_t size;
} hash_table_t;

/*
	hash table functions
	copyright (c) 2005 dr. srinidhi varadarajan
*/

/*

	creates a hash table and returns a pointer to it

	parameters:
	hash_table_size : size of the hash table to create

	returns: pointer to created hash table or NULL on failure

*/

static inline hash_table_t *create_hash_table(uint32_t hash_table_size)
{
	uint32_t t;
	hash_table_t *hash_table;

	hash_table = ( hash_table_t *) malloc(sizeof( hash_table_t));
	if (hash_table == NULL) return(NULL);

	hash_table->row = ( hash_entry_t **) malloc(sizeof( hash_entry_t *) * (hash_table_size));
	if (hash_table->row == NULL) return(NULL);

	hash_table->tail = ( hash_entry_t **) malloc(sizeof( hash_entry_t *) * (hash_table_size));
	if (hash_table->tail == NULL) return(NULL);

#ifdef __USE_HASH_LOCKS__
	hash_table->row_lock = (sem_t *) malloc(sizeof(sem_t) * (hash_table_size + 2));
	if (hash_table->row_lock == NULL) return(NULL);
#endif

	for (t=0; t<hash_table_size; t++)
	{
		hash_table->row[t] = NULL;
		hash_table->tail[t] = NULL;
#ifdef __USE_HASH_LOCKS__
		sem_init(&hash_table->row_lock[t], 0, 1);
#endif
	}

	hash_table->size = hash_table_size;
	return(hash_table);
}

/*
	inserts a structure into the hash table.

	parameters :
	hash_table : Hash table to use
	key : key to index the hash table
	key_len: length of the hash key in bytes
	data : pointer to the data to insert. you should allocate and free the
	data pointer within your application

	returns:
	TRUE if key was inserted into the table
	FALSE if key could not be inserted into the table

	note: a data element can be inserted more than once in this
	hash structure. be careful when you use hash_insert to make sure
	that if you insert multiple times, you also delete multiple times.
*/
static inline int32_t hash_insert( hash_table_t *hash_table, void *key, uint32_t key_len, void *data)
{
	uint32_t hash_key, hash_table_size;
	hash_entry_t *new_entry, *prev_ptr;

	hash_table_size = hash_table->size;

	hash_key  = hash(key, key_len, 7) % hash_table_size;

#ifdef __USE_HASH_LOCKS__
	sem_wait(&hash_table->row_lock[hash_key]);
#endif

	new_entry = ( hash_entry_t *) malloc(sizeof( hash_entry_t));
	if (new_entry == NULL)
	{
#ifdef __USE_HASH_LOCKS__
		sem_post(&hash_table->row_lock[hash_key]);
#endif
		return(FALSE);
	}

	new_entry->key = (char *) malloc(key_len);
	if (new_entry->key == NULL)
	{
		printf("Warning: Unable to allocate memory for hash key. \n");
		free(new_entry);
#ifdef __USE_HASH_LOCKS__
		sem_post(&hash_table->row_lock[hash_key]);
#endif
		return(FALSE);
	}

	prev_ptr = hash_table->tail[hash_key];
	new_entry->next = NULL;
	new_entry->prev = hash_table->tail[hash_key];
	if (prev_ptr == NULL)
		hash_table->row[hash_key] = new_entry;
	else
		prev_ptr->next = new_entry;

	hash_table->tail[hash_key] = new_entry;
	memcpy(new_entry->key, key, key_len);
	new_entry->data = data;
	new_entry->key_len = key_len;
#ifdef __USE_HASH_LOCKS__
	sem_post(&hash_table->row_lock[hash_key]);
#endif
	return(TRUE);
}

/*
	deletes a hash table entry.

	parameters :
	hash_table : hash table to use
	key : key to index the hash table
	key_len: length of the key in bytes

	returns:
	TRUE: if key was successfully deleted
	FALSE: if key could not be deleted (key was not found)

*/
static inline int32_t hash_delete( hash_table_t *hash_table, void *key, uint32_t key_len)
{
	uint32_t hash_key, hash_table_size;
	hash_entry_t *ptr, *prev_ptr;

	hash_table_size = hash_table->size;

	hash_key  = hash(key, key_len, 7) % hash_table_size;

#ifdef __USE_HASH_LOCKS__
	sem_wait(&(hash_table->row_lock[hash_key]));
#endif

	ptr = hash_table->row[hash_key];
	prev_ptr = NULL;

	while (ptr != NULL)
	{
		if (memcmp(ptr->key, key, key_len) == 0)
		{
			if (prev_ptr == NULL) // First entry
				hash_table->row[hash_key] = ptr->next;
			else
				prev_ptr->next = ptr->next;

			if (ptr->next == NULL) hash_table->tail[hash_key] = prev_ptr;

			free(ptr->key);
			free(ptr);
#ifdef __USE_HASH_LOCKS__
			sem_post(&hash_table->row_lock[hash_key]);
#endif
			return(TRUE);
		}
		prev_ptr = ptr;
		ptr = ptr->next;
	}

#ifdef __USE_HASH_LOCKS__
	sem_post(&hash_table->row_lock[hash_key]);
#endif

	return(FALSE);
}


/*
	finds the entry corresponding to key in the hash table

	parameters:
	hash_table : pointer to the hash table to use
	key : key to index the hash table.
	key_len: length of the key in bytes

	returns:
	pointer to the data field in the hash table on success
	NULL on failure
*/
static inline void *hash_find( hash_table_t *hash_table, void *key, uint32_t key_len)
{
	uint32_t hash_key, hash_table_size;
	hash_entry_t *ptr;


	hash_table_size = hash_table->size;

	hash_key  = hash(key, key_len, 7) % hash_table_size;

#ifdef __USE_HASH_LOCKS__
	sem_wait(&hash_table->row_lock[hash_key]);
#endif

	ptr = hash_table->row[hash_key];
	while (ptr != NULL)
	{
		if ((key_len == ptr->key_len) && (memcmp(ptr->key, key, key_len) == 0))
		{
#ifdef __USE_HASH_LOCKS__
			sem_post(&hash_table->row_lock[hash_key]);
#endif
			return(ptr->data);
		}
		ptr = ptr->next;
	}
#ifdef __USE_HASH_LOCKS__
	sem_post(&hash_table->row_lock[hash_key]);
#endif
	return(NULL);
}

/*
	destroys the hash table and frees all allocated memory

	parameters:
	hash_table : pointer to the hash table to use

	returns : nothing
*/

static inline void destroy_hash_table( hash_table_t *hash_table)
{
	uint32_t t, count, max_count=0, tot_count=0, hash_table_size;
	hash_entry_t *cur_ptr, *tmp_ptr;

	hash_table_size = hash_table->size;

	for (t=0; t<hash_table_size; t++)
	{
#ifdef __USE_HASH_LOCKS__
		sem_wait(&hash_table->row_lock[t]);
#endif
		if (hash_table->row[t] != NULL)
		{
			cur_ptr = hash_table->row[t];
			count = 1;
			while (cur_ptr != NULL)
			{
				free(cur_ptr->key);
				tmp_ptr = cur_ptr->next;
				free(cur_ptr);
				cur_ptr = tmp_ptr;
				count++;
			}
			hash_table->row[t] = NULL;
			tot_count += count;
			if (count > max_count) max_count = count;
		}
#ifdef __USE_HASH_LOCKS__
		sem_post(&hash_table->row_lock[t]);
#endif
	}

	printf("Max collision list entries: %u. Total: %u\n", max_count, tot_count);
	free(hash_table->row);
	free(hash_table->tail);

#ifdef __USE_HASH_LOCKS__
	free(hash_table->row_lock);
#endif

	free(hash_table);
}

#endif
