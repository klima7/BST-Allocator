#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include "custom_unistd.h"

#define MM_HIDE_RAPORT

#define PAGE_SIZE 4096
#define PAGE_FENCE      1       
#define PAGES_AVAILABLE 16384   
#define PAGES_TOTAL     (PAGES_AVAILABLE + 2 * PAGE_FENCE)

uint8_t memory[PAGE_SIZE * PAGES_TOTAL] __attribute__((aligned(PAGE_SIZE)));

struct memory_fence_t {
    uint8_t first_page[PAGE_SIZE];
    uint8_t last_page[PAGE_SIZE];
};

struct mm_struct {
    intptr_t start_brk;
    intptr_t brk;
    
    struct memory_fence_t fence;
    intptr_t start_mmap;
	
	intptr_t limit;
} mm;

void __attribute__((constructor)) memory_init(void)
{
    setvbuf(stdout, NULL, _IONBF, 0); 
    srand(time(NULL));
    assert(sizeof(intptr_t) == sizeof(void*));
	
	mm.limit = -1;
    
    for (int i = 0; i < PAGE_SIZE; i++) {
        mm.fence.first_page[i] = rand();
        mm.fence.last_page[i] = rand();
    }
    
    memcpy(memory, mm.fence.first_page, PAGE_SIZE);
    memcpy(memory + (PAGE_FENCE + PAGES_AVAILABLE) * PAGE_SIZE, mm.fence.last_page, PAGE_SIZE);

    mm.start_brk = (intptr_t)(memory + PAGE_SIZE);
    mm.brk = (intptr_t)(memory + PAGE_SIZE);
    mm.start_mmap = (intptr_t)(memory + (PAGE_FENCE + PAGES_AVAILABLE) * PAGE_SIZE);
    
    assert(mm.start_mmap - mm.start_brk == PAGES_AVAILABLE * PAGE_SIZE);
} 

void __attribute__((destructor)) memory_check(void)
{
	#ifndef MM_HIDE_RAPORT
    int first = memcmp(memory, mm.fence.first_page, PAGE_SIZE);
    int last = memcmp(memory + (PAGE_FENCE + PAGES_AVAILABLE) * PAGE_SIZE, mm.fence.last_page, PAGE_SIZE);
    
    printf("\n### Stan płotków przestrzeni sterty:\n");
    printf("    Płotek początku: [%s]\n", first == 0 ? "poprawny" : "USZKODZONY");
    printf("    Płotek końca...: [%s]\n", last == 0 ? "poprawny" : "USZKODZONY");

    printf("### Podsumowanie: \n");
        printf("    Całkowita przestrzeni pamięci....: %lu bajtów\n", mm.start_mmap - mm.start_brk);
        printf("    Pamięć zarezerwowana przez sbrk(): %lu bajtów\n", mm.brk - mm.start_brk);
	#endif
}


void set_mem_limit(intptr_t limit)
{
	mm.limit = mm.start_brk + limit;
}

void* custom_sbrk(intptr_t delta)
{
    intptr_t current_brk = mm.brk;
    if (mm.start_brk + delta < 0) {
        errno = 0;
        return (void*)current_brk;
    }
    
    if (mm.brk + delta >= mm.start_mmap ||  (mm.limit != -1 && mm.brk + delta > mm.limit)) {
        errno = ENOMEM;
        return (void*)-1;
    }
    
    mm.brk += delta;
    return (void*)current_brk;
}