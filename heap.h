#ifndef __HEAP_H__
#define __HEAP_H__

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <string.h>

#ifdef DEBUG
#define log(__str, __arg...) print_log(__str, ## __arg)
#else
#define log(__str, __arg...) 
#endif

#define BLOCK2CHUNK(__block) 	((BLOCK *)(__block) + 1)
#define CHUNK2BLOCK(__chunk) 	((BLOCK *)(__chunk) - 1)
#define WORD_LEN				sizeof(void *)
#define ROUND_TO_WORD(__size)	((__size)+(WORD_LEN-(__size)%WORD_LEN)%WORD_LEN)
#define PATH2FILENAME(__path)	(strrchr(__path, '/') + 1)

#define malloc(__COUNT)				heap_malloc_debug(__COUNT, __LINE__, PATH2FILENAME(__FILE__))
#define calloc(__NUMBER, __SIZE)	heap_calloc_debug(__NUMBER, __SIZE, __LINE__, PATH2FILENAME(__FILE__))	
#define realloc(__BLOCK, __SIZE)	heap_realloc_debug(__BLOCK, __SIZE, __LINE__, PATH2FILENAME(__FILE__))

#define malloc_aligned(__COUNT)				heap_malloc_aligned_debug(__COUNT, __LINE__, PATH2FILENAME(__FILE__))
#define calloc_aligned(__NUMBER, __SIZE)	heap_calloc_aligned_debug(__NUMBER, __SIZE, __LINE__, PATH2FILENAME(__FILE__))
#define realloc_aligned(__BLOCK, __SIZE)	heap_realloc_aligned_debug(__BLOCK, __SIZE, __LINE__, PATH2FILENAME(__FILE__))

#define free(__PTR)		heap_free(__PTR)

#define SBRK_FAIL 	((void*)-1)
#define PAGE_SIZE 	4096
#define BLOCK_SIZE 	sizeof(BLOCK)

typedef void *CHUNK;

typedef struct heap_block_t
{
	uint32_t left_fence;
	
	uint32_t checksum;
	
	struct heap_block_t *prev;
	struct heap_block_t *next;
	
	struct heap_block_t *parent;
	struct heap_block_t *left;
	struct heap_block_t *right;
	
	const char *filaname;
	int line;
	
	size_t size;
	bool free;
	
	uint32_t right_fence;
} BLOCK;

typedef struct heap_t
{
	bool initialized;
	
	BLOCK *head;
	BLOCK *tail;
	
	BLOCK *free_root;
	BLOCK *used_root;
	
	uint64_t blocks;
	
	uint32_t left_fence;
	uint32_t right_fence;
	
	uint32_t checksum;
} HEAP;

enum pointer_type_t
{
	pointer_null,
	pointer_out_of_heap,
	pointer_control_block,
	pointer_inside_data_block,
	pointer_unallocated,
	pointer_valid
};

int heap_setup(void);

void *heap_malloc(size_t count);
void *heap_calloc(size_t number, size_t size);
void  heap_free(void* memblock);
void *heap_realloc(void* memblock, size_t size);

void* heap_malloc_debug(size_t count, int fileline, const char* filename);
void* heap_calloc_debug(size_t number, size_t size, int fileline, const char* filename);
void* heap_realloc_debug(void* memblock, size_t size, int fileline, const char* filename);

void* heap_malloc_aligned(size_t count);
void* heap_calloc_aligned(size_t number, size_t size);
void* heap_realloc_aligned(void* memblock, size_t size);

void* heap_malloc_aligned_debug(size_t count, int fileline, const char* filename);
void* heap_calloc_aligned_debug(size_t number, size_t size, int fileline, const char* filename);
void* heap_realloc_aligned_debug(void* memblock, size_t size, int fileline, const char* filename);

size_t heap_get_used_space(void);
size_t heap_get_largest_used_block_size(void);
uint64_t heap_get_used_blocks_count(void);
size_t heap_get_free_space(void);
size_t heap_get_largest_free_area(void);
uint64_t heap_get_free_gaps_count(void);

enum pointer_type_t get_pointer_type(const void* pointer);
void* heap_get_data_block_start(const void* pointer);
size_t heap_get_block_size(const void* memblock);
int heap_validate(void);
void heap_dump_debug_information(void);

#endif