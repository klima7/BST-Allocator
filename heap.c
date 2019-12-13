/*
 * Alokator realizuję strategię "best fit".
 * Jest oparty na dwóch drzewach binarnych, jedno zawiera bloki wolne, a drugie zawiera bloki zaalokowane.
 * Drzewo bloków wolnych służy do znajdowania najlepiej dopasowanych bloków w średnim czasie logarytmicznym.
 * Drzewo bloków zajętych służy do sprawdzania w czasie zwalniania bloku, czy przekazywany wskaźnik jest poprawny.
 * 
 */

#define DEBUG

#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include <string.h>
#include <assert.h>
#include "custom_unistd.h"
#include "colors.h"
#include "heap.h"

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static HEAP heap;

static void print_log(const char *str, ...)
{
	va_list list;
	va_start(list, str);
	printf(COLOR_YELLOW);
	vprintf(str, list);
	printf(COLOR_RESET "\n");
	va_end(list);
}

static uint32_t calculate_checksum(void *start, void *end)
{
	uint8_t *start_byte = (uint8_t *)start;
	uint8_t *end_byte = (uint8_t *)end;
	
	uint32_t checksum = 0;
	
	for(; start_byte < end_byte; start_byte++)
		checksum += *start_byte;
		
	return checksum;
}

static void block_set_fences(BLOCK *block)
{
	block->left_fence = heap.left_fence;
	block->right_fence = heap.right_fence;
}

static bool block_check_fences(BLOCK *block)
{
	if(block->left_fence != heap.left_fence || block->right_fence != heap.right_fence)
		return false;
	else return true;
}

static void block_set_checksum(BLOCK *block)
{
	block->checksum = 0;
	block->checksum = calculate_checksum(block, block+1);
}

static bool block_check_checksum(BLOCK *block)
{
	uint32_t checksum = block->checksum;
	block_set_checksum(block);
	if(block->checksum == checksum) return true;
	else return false;
}

static void heap_set_checksum(void)
{
	heap.checksum = 0;
	heap.checksum = calculate_checksum(&heap, &heap+1);
}

static bool heap_check_checksum(void)
{
	uint32_t checksum = heap.checksum;
	heap_set_checksum();
	if(heap.checksum == checksum) return true;
	else return false;
}

static void heap_lock(void)
{
	pthread_mutex_lock(&mutex);
}

static void heap_unlock(void)
{
	pthread_mutex_unlock(&mutex);
}

static void bst_insert(BLOCK **root, BLOCK *block)
{
	block->left = NULL;
	block->right = NULL;
	
	BLOCK *parent = NULL;
	BLOCK *current = *root;
	
	while(current != NULL)
	{
		parent = current;
		if(block->size < current->size)
			current = current->left;
		else
			current = current->right;
	}
	
	block->parent = parent;
	
	if(parent == NULL)
	{
		*root = block;
		heap_set_checksum();
	}
	else
	{
		if(block->size < parent->size)
			parent->left = block;
		else
			parent->right = block;
	}
	
	block_set_checksum(block);
	if(parent) block_set_checksum(parent);
}

static BLOCK *bst_find(BLOCK *root, size_t size)
{
	BLOCK *best_block = NULL;
	BLOCK *current = root;
	
	while(current != NULL)
	{
		if(current->size >= size)
			best_block = current;
			
		if(size == current->size)
			break;
		else if(size < current->size)
			current = current->left;
		else 
			current = current->right;
	}
	return best_block;
}

static BLOCK *bst_minimum(BLOCK *root)
{
	while(root->left != NULL)
		root = root->left;
	return root;
}

static BLOCK *bst_maximum(BLOCK *root)
{
	while(root->right != NULL)
		root = root->right;
	return root;
}

static BLOCK *bst_successor(BLOCK *block)
{
	if(block->right)
		return bst_minimum(block->right);
		
	BLOCK *prev = block;
	BLOCK *current = block->parent;
	
	while(current != NULL && prev == current->right)
	{
		prev = current;
		current = current->parent;
	}
	
	return current;
}

static BLOCK *bst_find_aligned(BLOCK *root, size_t size)
{
	BLOCK *current = bst_find(root, size);
	
	while(current != NULL)
	{
		intptr_t start_pos = (intptr_t)(current+1);
		intptr_t aligned_pos = start_pos + (PAGE_SIZE-start_pos%PAGE_SIZE)%PAGE_SIZE;
		intptr_t diff = aligned_pos - start_pos;
		
		if(current->size >= diff && current->size - diff >= size) 
			break;
		
		current = bst_successor(current);
	}
	
	return current;
}

static bool bst_contains(BLOCK *root, BLOCK *block)
{
	BLOCK *current = root;
	
	while(current != NULL)
	{
		if(current == block) return true;
			
		if(block->size < current->size)
			current = current->left;
		else 
			current = current->right;
	}
	return false;
}

static void bst_remove(BLOCK **root, BLOCK *block)
{
	// No childs
	if(block->left == NULL && block->right == NULL)
	{
		BLOCK *parent = block->parent;
		if(parent == NULL)
		{
			*root = NULL;
			heap_set_checksum();
			return;
		}
		BLOCK **connection_to_remove = parent->left == block ? &parent->left : &parent->right;			
		*connection_to_remove = NULL;
		block_set_checksum(parent);
	}
	
	// Two childs
	else if(block->left != NULL && block->right != NULL)
	{
		BLOCK *successor = bst_successor(block);
		BLOCK *parent = block->parent;
		bst_remove(root, successor);
		BLOCK **connection_to_block = NULL;
		
		if(parent == NULL)
			connection_to_block = root;
		else
			connection_to_block = parent->left == block ? &parent->left : &parent->right;
			
		*connection_to_block = successor;
		successor->left = block->left;
		successor->right = block->right;
		if(block->left)
		{
			block->left->parent = successor;
			block_set_checksum(block->left);
		}
		if(block->right)
		{
			block->right->parent = successor;
			block_set_checksum(block->right);
		}
		successor->parent = parent;
		block_set_checksum(successor);
		if(parent == NULL) heap_set_checksum();
		else block_set_checksum(parent);
	}
	
	// One child
	else
	{
		BLOCK *parent = block->parent;
		if(parent == NULL)
		{
			BLOCK *new_root = block->left!=NULL ? block->left : block->right;
			new_root->parent = NULL;
			*root = new_root;
			heap_set_checksum();
			block_set_checksum(new_root);
			return;
		}
		
		BLOCK **parent_child = parent->left == block ? &parent->left : &parent->right;			
		BLOCK *child = block->left != NULL ? block->left : block->right;

		*parent_child = child;
		child->parent = parent;
		
		block_set_checksum(parent);
		block_set_checksum(child);
	}
}

static void bst_get_nodes_count(BLOCK *node, size_t *blocks)
{
	if(!node) return;
	bst_get_nodes_count(node->left, blocks);
	bst_get_nodes_count(node->right, blocks);
	if(node->size >= WORD_LEN) *blocks = *blocks + 1;
}

static BLOCK *join_blocks(BLOCK *first, bool free_res)
{
	BLOCK *second = first->next;
	
	if(first->free) bst_remove(&heap.free_root, first);
	else bst_remove(&heap.used_root, first);
	if(second->free) bst_remove(&heap.free_root, second);
	else bst_remove(&heap.used_root, second);
		
	first->size += second->size + BLOCK_SIZE;
	first->next = second->next;
	second->next->prev = first;
	first->free = free_res;
	
	if(free_res) bst_insert(&heap.free_root, first);
	else bst_insert(&heap.used_root, first);
	
	block_set_checksum(first);
	block_set_checksum(second->next);
	
	heap.blocks--;
	heap_set_checksum();
	
	return first;
}

BLOCK *get_pages_from_os(intptr_t pages)
{
	// Możliwe przepełnienie
	intptr_t bytes = pages * PAGE_SIZE;
	if(bytes / PAGE_SIZE != pages) return NULL; 
	
	void *new_memory = custom_sbrk(bytes);
	if(new_memory == SBRK_FAIL) return NULL;
	
	BLOCK *new_free = heap.tail;
	BLOCK *new_guard = (BLOCK *)((intptr_t)new_memory + bytes) - 1;
	
	heap.tail = new_guard;
	
	new_guard->free = false;
	new_guard->prev = new_free;
	new_guard->next = NULL;
	new_guard->size = 0;
	
	block_set_fences(new_guard);
	block_set_checksum(new_guard);
	
	heap.blocks++;
	heap_set_checksum();
	
	new_free->free = true;
	new_free->next = new_guard;
	new_free->size = bytes - BLOCK_SIZE;
	
	bst_insert(&heap.free_root, new_free);
	block_set_checksum(new_free);

	if(new_free->prev->free)
		new_free = join_blocks(new_free->prev, true);
	return new_free;
}

static void return_pages_to_os(void)
{
	BLOCK *last_block = heap.tail->prev;
	
	if(!last_block->free)
		return;
		
	if(last_block->size >= PAGE_SIZE)
	{
		intptr_t pages_count = last_block->size / PAGE_SIZE;
		intptr_t bytes_count = pages_count * PAGE_SIZE;
		
		BLOCK *guard = (BLOCK *)((intptr_t)heap.tail - bytes_count);
		BLOCK *free = last_block;
		
		bst_remove(&heap.free_root, last_block);
		
		void *new_memory = custom_sbrk(-bytes_count);
		assert(new_memory != SBRK_FAIL);
		
		guard->next = NULL;
		guard->prev = free;
		guard->size = 0;
		guard->free = false;
		
		free->next = guard;
		free->size -= bytes_count;
		
		bst_insert(&heap.free_root, free);
		
		heap.tail = guard;
		heap_set_checksum();
		
		block_set_fences(guard);
		block_set_checksum(guard);
		block_set_checksum(free);
	}
}

static BLOCK *split_block(BLOCK *block, size_t size, bool free1, bool free2)
{	
	if(block->free) bst_remove(&heap.free_root, block);
	else bst_remove(&heap.used_root, block);
	
	BLOCK *first_block = block;
	BLOCK *second_block = (BLOCK*)((intptr_t)(first_block+1)+size);
	
	block->next->prev = second_block; 
	block_set_checksum(block->next);
	
	second_block->free = free2;
	second_block->size = block->size - size - BLOCK_SIZE;
	second_block->prev = first_block;
	second_block->next = block->next;
	
	first_block->free = free1;
	first_block->size = size;
	first_block->next = second_block;
	
	if(free1) bst_insert(&heap.free_root, first_block);
	else bst_insert(&heap.used_root, first_block);
	if(free2) bst_insert(&heap.free_root, second_block);
	else bst_insert(&heap.used_root, second_block);
	
	block_set_fences(second_block);
	block_set_checksum(first_block);
	block_set_checksum(second_block);
	
	heap.blocks++;
	heap_set_checksum();
	
	return second_block;
}

static BLOCK *block_change_size(BLOCK *block, intptr_t delta)
{
	bst_remove(&heap.free_root, block->next);
	
	BLOCK *new_next = (BLOCK *)((intptr_t)block->next + delta);
	
	block->next->next->prev = new_next;
	block_set_checksum(block->next->next);
	
	memmove(new_next, block->next, BLOCK_SIZE);
	
	block->size += delta;
	block->next = new_next;
	
	new_next->size -= delta;
	new_next->prev = block;
	
	bst_insert(&heap.free_root, new_next);
	
	block_set_checksum(new_next);
	block_set_checksum(block);
	
	return new_next;
}

int heap_setup(void)
{	
	heap_lock();
	
	if(heap.initialized)
	{
		log("Heap is already initialized");
		heap_unlock();
		return 0;
	}
	
	void *memory = custom_sbrk(PAGE_SIZE);
	if(memory == SBRK_FAIL)
	{
		heap_unlock();
		return -1;
	}
		
	BLOCK *left_guard = (BLOCK *)memory;
	BLOCK *free_block = left_guard+1;
	BLOCK *right_guard = (BLOCK *)((intptr_t)memory + PAGE_SIZE) - 1;
	
	heap.head = left_guard;
	heap.tail = right_guard;
	heap.free_root = NULL;
	heap.used_root = NULL;
	
	left_guard->prev = NULL;
	left_guard->next = free_block;
	left_guard->size = 0;
	left_guard->free = false;
	
	free_block->prev = left_guard;
	free_block->next = right_guard;
	free_block->size = PAGE_SIZE - 3*BLOCK_SIZE;
	free_block->free = true;
	
	right_guard->prev = free_block;
	right_guard->next = NULL;
	right_guard->size = 0;
	right_guard->free = false;
	
	heap.left_fence = rand();
	heap.right_fence = rand();
	
	block_set_fences(left_guard);
	block_set_fences(free_block);
	block_set_fences(right_guard);
	
	bst_insert(&heap.free_root, free_block);
	
	block_set_checksum(left_guard);
	block_set_checksum(free_block);
	block_set_checksum(right_guard);
		
	heap.blocks = 3;
	
	heap.initialized = true;
	heap_set_checksum();
	heap_unlock();
	return 0;
}

static void* heap_malloc_debug_NOT_THREADSAVE(size_t count, int fileline, const char* filename)
{
	if(count == 0 || !heap.initialized)
		return NULL;
	
	count = ROUND_TO_WORD(count);
		
	BLOCK *block = bst_find(heap.free_root, count);
	
	if(block == NULL)
	{
		size_t already_have = 0;
		
		BLOCK *last_block = heap.tail->prev;
		if(last_block->free)
			already_have = last_block->size + BLOCK_SIZE;
		size_t need_bytes = count - already_have + BLOCK_SIZE;
		intptr_t need_pages = need_bytes / PAGE_SIZE;
		if(need_bytes % PAGE_SIZE != 0) need_pages++;
		
		block = get_pages_from_os(need_pages);
		if(block == NULL) return NULL;
	}	
	
	if(block->size - count >= BLOCK_SIZE)
		split_block(block, count, true, true);

	block->free = false;
	block->filaname = filename;
	block->line = fileline;
	bst_remove(&heap.free_root, block);
	bst_insert(&heap.used_root, block);
	
	block_set_checksum(block);
	return BLOCK2CHUNK(block);
}

static void* heap_calloc_debug_NOT_THREADSAVE(size_t number, size_t size, int fileline, const char* filename)
{		
	if(number == 0 || size == 0 || !heap.initialized)
		return NULL;
	
	size_t count = number * size;
	
	if(count / number != size)
	{
		log("CALLOC: Overflow");
		return NULL;
	}

	void *chunk = heap_malloc_debug_NOT_THREADSAVE(count, fileline, filename);

	if(chunk != NULL)
		memset(chunk, 0, count);
		
	return chunk;
}

static void  heap_free_NOT_THREADSAVE(void* memblock)
{
	if(memblock == NULL || !heap.initialized)
		return;
		
	BLOCK *block = CHUNK2BLOCK(memblock);
		
	if(!bst_contains(heap.used_root, block))
	{
		log("HEAP_FREE: Invalid pointer");
		return;
	}
	
	block->free = true;
	block_set_checksum(block);
	bst_remove(&heap.used_root, block);
	bst_insert(&heap.free_root, block);
	block_set_checksum(block);
	if(block->prev->free)
	block = join_blocks(block->prev, true);
	
	if(block->next->free)
		block = join_blocks(block, true);
	
	return_pages_to_os();
}

static void* heap_realloc_debug_NOT_THREADSAVE(void* memblock, size_t size, int fileline, const char* filename)
{
	if(!heap.initialized)
		return NULL;
	
	if(memblock == NULL)
		return heap_malloc_debug_NOT_THREADSAVE(size, fileline, filename);

	if(size == 0)
	{
		heap_free_NOT_THREADSAVE(memblock);
		return NULL;
	}
	
	BLOCK *block = CHUNK2BLOCK(memblock);
	BLOCK *next = block->next;
	size = ROUND_TO_WORD(size);
	intptr_t delta = size - block->size;
	
	block->filaname = filename;
	block->line = fileline;

	if(delta < 0)
	{
		if(next->free)
			block_change_size(block, delta);
		else if(-delta >= BLOCK_SIZE)
			split_block(block, size, false, true);		
		return_pages_to_os();
		return memblock;
	}
	
	else if(delta > 0)
	{
		if(next->free && next->size + BLOCK_SIZE >= delta)
		{
			join_blocks(block, false);
			if(-delta >= BLOCK_SIZE)
				split_block(block, size, false, true);
			return memblock;
		}
		
		else
		{
			void *new_chunk = heap_malloc_debug_NOT_THREADSAVE(size, fileline, filename);
			if(new_chunk == NULL) return NULL;
			memcpy(new_chunk, memblock, block->size);
			heap_free_NOT_THREADSAVE(memblock);
			return new_chunk;
		}
	}
	
	else
	{
		block_set_checksum(block);
		return memblock;
	}
}

void* heap_malloc_debug(size_t count, int fileline, const char* filename)
{
	heap_lock();
	void *ptr = heap_malloc_debug_NOT_THREADSAVE(count, fileline, filename);
	heap_unlock();
	return ptr;
}

void* heap_calloc_debug(size_t number, size_t size, int fileline, const char* filename)
{
	heap_lock();
	void *ptr = heap_calloc_debug_NOT_THREADSAVE(number, size, fileline, filename);
	heap_unlock();
	return ptr;
}

void* heap_realloc_debug(void* memblock, size_t size, int fileline, const char* filename)
{
	heap_lock();
	void *ptr = heap_realloc_debug_NOT_THREADSAVE(memblock, size, fileline, filename);
	heap_unlock();
	return ptr;
}

void  heap_free(void* memblock)
{
	heap_lock();
	heap_free_NOT_THREADSAVE(memblock);
	heap_unlock();
}

void *heap_malloc(size_t count) 
{
	return heap_malloc_debug(count, 0, NULL);
}

void *heap_calloc(size_t number, size_t size)
{
	return heap_calloc_debug(number, size, 0, NULL);
}

void *heap_realloc(void* memblock, size_t size)
{
	return heap_realloc_debug(memblock, size, 0, NULL);
}

static void* heap_malloc_aligned_debug_NOT_THREADSAVE(size_t count, int fileline, const char* filename)
{
	if(count == 0 || !heap.initialized)
		return NULL;
	
	count = ROUND_TO_WORD(count);
		
	BLOCK *block = bst_find_aligned(heap.free_root, count);
	
	if(block == NULL)
	{
		BLOCK *last = heap.tail->prev;
		
		intptr_t start_pos = (intptr_t)(block+1);
		intptr_t aligned_pos = start_pos + (PAGE_SIZE-start_pos%PAGE_SIZE)%PAGE_SIZE;
		intptr_t already_have = last->size - aligned_pos + start_pos;
		intptr_t need_bytes = count - already_have + BLOCK_SIZE;
		intptr_t need_pages = need_bytes / PAGE_SIZE;
		if(need_bytes % PAGE_SIZE != 0) need_pages++;
		
		block = get_pages_from_os(need_pages);
		if(block == NULL) return NULL;
	}	
	
	intptr_t start_pos = (intptr_t)(block+1);
	intptr_t aligned_pos = start_pos + (PAGE_SIZE-start_pos%PAGE_SIZE)%PAGE_SIZE;
	
	intptr_t first_size = aligned_pos - start_pos;

	if(first_size >= BLOCK_SIZE)
		block = split_block(block, first_size - BLOCK_SIZE, true, true);
	else if(first_size != 0)
		block = block_change_size(block->prev, first_size);
	
	intptr_t second_size = block->size - count;
	
	if(second_size >= BLOCK_SIZE)
		split_block(block, count, true, true);

	block->free = false;
	block->filaname = filename;
	block->line = fileline;
	bst_remove(&heap.free_root, block);
	bst_insert(&heap.used_root, block);
	
	block_set_checksum(block);	
	return BLOCK2CHUNK(block);
}

static void* heap_calloc_aligned_debug_NOT_THREADSAVE(size_t number, size_t size, int fileline, const char* filename)
{
	if(number == 0 || size == 0 || !heap.initialized)
		return NULL;
	
	size_t count = number * size;
	
	if(count / number != size)
	{
		log("CALLOC: Calloc overflow");
		return NULL;
	}
	
	void *chunk = heap_malloc_aligned_debug_NOT_THREADSAVE(count, fileline, filename);
	
	if(chunk != NULL)
		memset(chunk, 0, count);
		
	return chunk;
}

static void* heap_realloc_aligned_debug_NOT_THREADSAVE(void* memblock, size_t size, int fileline, const char* filename)
{
	if(!heap.initialized)
		return NULL;
	
	if(memblock == NULL)
		return heap_malloc_aligned_debug_NOT_THREADSAVE(size, fileline, filename);
		
	if(size == 0)
	{
		heap_free_NOT_THREADSAVE(memblock);
		return NULL;
	}
	
	BLOCK *block = CHUNK2BLOCK(memblock);
	BLOCK *next = block->next;
	size = ROUND_TO_WORD(size);
	intptr_t delta = size - block->size;
	bool is_aligned = ((intptr_t)memblock & (intptr_t)(PAGE_SIZE - 1)) == 0;
	
	block->filaname = filename;
	block->line = fileline;
	
	if(!is_aligned)
	{
		void *new_chunk = heap_malloc_aligned_debug_NOT_THREADSAVE(size, fileline, filename);
		if(new_chunk == NULL) return NULL;
		memcpy(new_chunk, memblock, size);
		heap_free_NOT_THREADSAVE(memblock);
		return new_chunk;
	}

	if(delta < 0)
	{
		if(next->free)
			block_change_size(block, delta);
		else if(-delta >= BLOCK_SIZE)
			split_block(block, size, false, true);	
		return_pages_to_os();
		return memblock;
	}
	
	else if(delta > 0)
	{
		if(next->free && next->size + BLOCK_SIZE >= delta)
		{
			join_blocks(block, false);
			if(-delta >= BLOCK_SIZE)
				split_block(block, size, false, true);
			return memblock;
		}
		
		else
		{
			void *new_chunk = heap_malloc_aligned_debug_NOT_THREADSAVE(size, fileline, filename);
			if(new_chunk == NULL) return NULL;
			memcpy(new_chunk, memblock, block->size);
			heap_free_NOT_THREADSAVE(memblock);
			return new_chunk;
		}
	}
	
	else
		return memblock;
}

void* heap_malloc_aligned_debug(size_t count, int fileline, const char* filename)
{
	heap_lock();
	void *ptr = heap_malloc_aligned_debug_NOT_THREADSAVE(count, fileline, filename);
	heap_unlock();
	return ptr;
}

void* heap_calloc_aligned_debug(size_t number, size_t size, int fileline, const char* filename)
{
	heap_lock();
	void *ptr = heap_calloc_aligned_debug_NOT_THREADSAVE(number, size, fileline, filename);
	heap_unlock();
	return ptr;
}

void* heap_realloc_aligned_debug(void* memblock, size_t size, int fileline, const char* filename)
{
	heap_lock();
	void *ptr = heap_realloc_aligned_debug_NOT_THREADSAVE(memblock, size, fileline, filename);
	heap_unlock();
	return ptr;
}

void* heap_malloc_aligned(size_t count)
{
	return heap_malloc_aligned_debug(count, 0, NULL);
}

void* heap_calloc_aligned(size_t number, size_t size)
{
	return heap_calloc_aligned_debug(number, size, 0, NULL);
}

void* heap_realloc_aligned(void* memblock, size_t size)
{
	return heap_realloc_aligned_debug(memblock, size, 0, NULL);
}

void heap_dump_debug_information(void)
{
	heap_lock();
	
	if(!heap.initialized)
	{
		printf("Heap is not initialized\n");
		heap_unlock();
		return;
	}
	
	printf("%5s |%20s |%10s |%15s |%10s |\n", "TYPE", "ADDRES", "SIZE", "FILE", "LINE");
	
	BLOCK *current = heap.head;
	while(current != NULL)
	{
		const char *type = current->free ? "FREE" : "USED";		
		if(!current->free && current->filaname != NULL)
			printf("%5s |%20p |%10u |%15s |%10d |\n", type, current, (unsigned int)current->size, current->filaname, current->line);
		else
			printf("%5s |%20p |%10u |%15s |%10s |\n", type, current, (unsigned int)current->size, "----", "----");
		current = current->next;
	}
	
	heap_unlock();
}

static int bst_validate(BLOCK *root, bool expected_free)
{
	
	if(!root) return 0;
	if(root->left && bst_validate(root->left, expected_free) == -1) return -1;
	if(root->right && bst_validate(root->right, expected_free) == -1) return -1;
	
	if((intptr_t)root->left & (WORD_LEN-1) || (intptr_t)root->right & (WORD_LEN-1) || (intptr_t)root->parent & (WORD_LEN-1))
	{
		log("VALIDATE ERROR: Indivisable by WORD_LEN value in block %p", root);
		return -1;
	}
	
	if(root->free != expected_free)
	{
		log("VALIDATE ERROR: Unexpected free value in tree node %p", root);
		return -1;
	}
		
	if(root->left && root->left->parent != root)
	{
		log("VALIDATE ERROR: Invalid parent pointer in block %p", root->left);
		return -1;
	}


	if(root->right && root->right->parent != root)
	{
		log("VALIDATE ERROR: Invalid parent pointer in block %p", root->right);
		return -1;
	}
	
	return 0;
}

int heap_validate(void)
{
	heap_lock();
	
	if(!heap.initialized || !heap_check_checksum()) 
	{
		heap_unlock();
		return -1;
	}
	
	BLOCK *prev = NULL;
	BLOCK *current = heap.head;
	
	for(int i=0; i<heap.blocks; i++)
	{
		if(!block_check_checksum(current) && 0) 
		{
			log("VALIDATE ERROR: Invalid checksum in block %d", i);
			heap_unlock();
			return -1;
		}
			
		if(!block_check_fences(current))
		{
			log("VALIDATE ERROR: Invalid fences in block %d", i);
			heap_unlock();
			return -1;
		}
			
		if(prev != NULL && current->prev != prev)
		{
			log("VALIDATE ERROR: Invalid prev pointer in block %d", i);
			heap_unlock();
			return -1;
		}
			
		if((intptr_t)current->next & (WORD_LEN-1) || (intptr_t)current->prev & (WORD_LEN-1) || current->size & (WORD_LEN-1))
		{
			log("VALIDATE ERROR: Indivisable by WORD_LEN value in block %d", i);
			heap_unlock();
			return -1;
		}
			
		if(i != heap.blocks - 1)
		{
			intptr_t proper_size = (intptr_t)current->next - (intptr_t)current - BLOCK_SIZE;
			if(current->size != (size_t)proper_size)
			{
				log("VALIDATE ERROR: Incoherent size and next pointer in block %d", i);
				heap_unlock();
				return -1;
			}
		}
		
		else if(current != heap.tail)
		{
			log("VALIDATE ERROR: Tail expected in block %d", i);
			heap_unlock();
			return -1;
		}
	
		prev = current;
		current = current->next;
	}
	
	if(bst_validate(heap.free_root, true) == -1)
	{
		log("VALIDATE ERROR: free blocks tree fails");
		heap_unlock();
		return -1;
	}
	
	if(bst_validate(heap.used_root, false) == -1)
	{
		log("VALIDATE ERROR: used blocks tree fails");
		heap_unlock();
		return -1;
	}
	
	heap_unlock();
	return 0;
}

size_t heap_get_used_space(void)
{
	heap_lock();
	if(!heap.initialized) 
	{
		heap_unlock();
		return 0;
	}
	
	size_t used_space = 0;
	
	BLOCK *current = heap.head;
	while(current != NULL)
	{
		used_space += BLOCK_SIZE;
		if(!current->free) used_space += current->size;
		current = current->next;
	}
	
	heap_unlock();
	return used_space;
}

uint64_t heap_get_used_blocks_count(void)
{
	heap_lock();
	if(!heap.initialized) 
	{
		heap_unlock();
		return 0;
	}
	uint64_t used_blocks = 0;
	bst_get_nodes_count(heap.used_root, &used_blocks);
	heap_unlock();
	return used_blocks;
}

size_t heap_get_largest_used_block_size(void)
{
	heap_lock();
	if(!heap.initialized || heap.used_root == NULL) 
	{
		heap_unlock();
		return 0;
	}
	BLOCK *largest = bst_maximum(heap.used_root);
	size_t largest_size = largest->size;
	heap_unlock();
	return largest_size;
}

static void bst_get_free_space(BLOCK *node, uint64_t *free_space)
{
	if(node->left) bst_get_free_space(node->left, free_space);
	if(node->right) bst_get_free_space(node->right, free_space);
	*free_space += node->size; 
}

size_t heap_get_free_space(void)
{
	heap_lock();
	if(!heap.initialized) 
	{
		heap_unlock();
		return 0;
	}
	size_t free_space = 0;
	bst_get_free_space(heap.free_root, &free_space);
	heap_unlock();
	return free_space;
}

size_t heap_get_largest_free_area(void)
{
	heap_lock();
	if(!heap.initialized || heap.free_root == NULL)
	{
		heap_unlock();
		return 0;
	}
	BLOCK *largest = bst_maximum(heap.free_root);
	heap_unlock();
	return largest->size;
}

uint64_t heap_get_free_gaps_count(void)
{
	heap_lock();
	if(!heap.initialized) 
	{
		heap_unlock();
		return 0;
	}
	uint64_t free_blocks = 0;
	bst_get_nodes_count(heap.free_root, &free_blocks);
	heap_unlock();
	return free_blocks;
}

enum pointer_type_t get_pointer_type(const void* pointer)
{
	if(pointer == NULL)
		return pointer_null;
		
	heap_lock();
		
	if(!heap.initialized || pointer < (void *)heap.head)
	{
		heap_unlock();
		return pointer_out_of_heap;
	}
		
	BLOCK *current = heap.head;
	
	while(current != NULL)
	{
		if(pointer >= (void *)current && pointer < (void *)(current+1))
		{
			heap_unlock();
			return pointer_control_block;
		}
		else if(pointer == current+1 && !current->free)
		{
			heap_unlock();
			return pointer_valid;
		}
		else if(pointer >= (void *)(current+1) && (uint8_t *)pointer < (uint8_t *)(current + 1)+current->size)
		{
			if(current->free)
			{
				heap_unlock();
				return pointer_unallocated;
			}
			else
			{
				heap_unlock();
				return pointer_inside_data_block;
			}
		}
		
		current = current->next;
	}
	heap_unlock();
	return pointer_out_of_heap;
}

static void bst_get_data_block_start(BLOCK *root, const void *ptr, void **block_start)
{
	if(!root) return;
	if(ptr >= (void *)(root + 1) && (uint8_t *)ptr < (uint8_t *)(root + 1)+root->size)
	{
		*block_start = (void *)(root + 1);
		return;
	}
	bst_get_data_block_start(root->left, ptr, block_start);
	bst_get_data_block_start(root->right, ptr, block_start);
}

void* heap_get_data_block_start(const void* pointer)
{		
	heap_lock();
	void *block_start = NULL;
	bst_get_data_block_start(heap.used_root, pointer, &block_start);
	heap_unlock();
	return block_start;
}

size_t heap_get_block_size(const void* memblock)
{
	heap_lock();
	BLOCK *block = CHUNK2BLOCK(memblock);
	
	if(!bst_contains(heap.used_root, block))
	{
		heap_unlock();
		return 0;
	}
	heap_unlock();
	return block->size;
}



