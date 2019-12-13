#include <stdio.h>
#include <stdint.h>
#include <check.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include "heap.h"
#include "colors.h"
#include "tests.h"
#include "custom_unistd.h"

#define DEFAULT_MAX_TIME 500000000

static bool is_aligned(void *ptr, uint32_t size)
{
	if(((uintptr_t)ptr & (size-1)) == 0)
		return true;
	else
		return false;
}

//------------------------TEST-----------------------------
TEST_START(heap_setup_1, TEST_FINISH, DEFAULT_MAX_TIME)
{
	// Inicjowanie sterty gdy dostępna jest pamięc kończy się sukcesem
	TEST_ASSERT(heap_setup() == 0)
	TEST_ASSERT(heap_validate() == 0);
}
TEST_END

//------------------------TEST-----------------------------
TEST_START(heap_setup_2, TEST_FINISH, DEFAULT_MAX_TIME)
{
	// Inicjowanie sterty przy braku pamięci zwraca błąd
	set_mem_limit(0);
	TEST_ASSERT(heap_setup() == -1)
}
TEST_END

//------------------------TEST-----------------------------
TEST_START(malloc_1, TEST_FINISH, DEFAULT_MAX_TIME)
{
	TEST_ASSERT(heap_setup() == 0)
	
	// Alokowanie zera bajtów zwraca NULL
	TEST_ASSERT(malloc(0) ==  NULL);
	
	// Alokowanie obszaru gdy dostępna jest pamięć zwraca wskaźnik wyrównany do słowa
	for(int i=1; i<100; i++)
	{
		void *ptr = malloc(i);
		TEST_ASSERT(ptr != NULL);
		TEST_ASSERT(is_aligned(ptr, WORD_LEN));
	}
	
	TEST_ASSERT(heap_validate() == 0);
}
TEST_END

//------------------------TEST-----------------------------
TEST_START(malloc_2, TEST_FINISH, DEFAULT_MAX_TIME)
{
	set_mem_limit(PAGE_SIZE);
	TEST_ASSERT(heap_setup() == 0)
	
	// Alokowanie obszaru gdy nie ma dostępnej pamięci zwraca NULL
	TEST_ASSERT(malloc(10000) == NULL);
	
	TEST_ASSERT(heap_validate() == 0);
}
TEST_END

//------------------------TEST-----------------------------
TEST_START(calloc_1, TEST_FINISH, DEFAULT_MAX_TIME)
{
	TEST_ASSERT(heap_setup() == 0)
	
	// Alokowanie zera bajtów zwraca NULL
	TEST_ASSERT(calloc(0, 5) ==  NULL);
	TEST_ASSERT(calloc(5, 0) ==  NULL);
	
	// Alokowanie obszaru gdy dostępna jest pamięć zwraca wskaźnik wyrównany do słowa z wyzerowaną pamięcią
	for(int j=1; j<100; j++)
	{
		uint8_t *ptr = (uint8_t *)calloc(j, 20);
		TEST_ASSERT(ptr != NULL);
		TEST_ASSERT(is_aligned(ptr, WORD_LEN));
		for(int i=0; i<j*20; i++)
			TEST_ASSERT(ptr[i] == 0);
	}
		
	// Podczas przepełnienia zwracany jest NULL
	size_t max = -1;
	TEST_ASSERT(calloc(max, 2) == NULL);
	TEST_ASSERT(calloc(max, max) == NULL);
	
	TEST_ASSERT(heap_validate() == 0);
}
TEST_END

//------------------------TEST-----------------------------
TEST_START(calloc_2, TEST_FINISH, DEFAULT_MAX_TIME)
{
	set_mem_limit(PAGE_SIZE);
	TEST_ASSERT(heap_setup() == 0)
	
	// Próba alokowania obszaru gdy nie ma pamięci zwraca NULL
	TEST_ASSERT(calloc(10000, 8) == NULL);
	
	TEST_ASSERT(heap_validate() == 0);
}
TEST_END

//------------------------TEST-----------------------------
TEST_START(realloc_1, TEST_FINISH, DEFAULT_MAX_TIME)
{
	TEST_ASSERT(heap_setup() == 0)
	
	// Realloc gdy wskaźnik jest równy NULL sprowadza się do alokacji
	void *ptr = realloc(NULL, 50);
	TEST_ASSERT(heap_get_used_blocks_count() == 1);
	
	// Realloc gdy rozmiar jest równy 0 sprowadza się do zwolnieia pamięci
	TEST_ASSERT(realloc(ptr, 0) == NULL);
	TEST_ASSERT(heap_get_used_blocks_count() == 0);
	
	// Po zmianie rozmiaru nowy obszar powinien zawierać te same dane co poprzedni
	int *ptr2 = (int *)malloc(sizeof(int));
	*ptr2 = 7;
	int *ptr3 = (int *)realloc(ptr2, 2 * sizeof(int));
	TEST_ASSERT(*ptr3 == 7);
	TEST_ASSERT(heap_validate() == 0);
}
TEST_END

//------------------------TEST-----------------------------
TEST_START(realloc_2, TEST_FINISH, DEFAULT_MAX_TIME)
{
	// Gdy wskaźńik jest równy NULL to realloc powinien zaalokować pamięć, ale nie ma jej wystarczająco
	set_mem_limit(PAGE_SIZE);
	TEST_ASSERT(heap_setup() == 0);
	TEST_ASSERT(realloc(NULL, 5000) == NULL);
	
	TEST_ASSERT(heap_validate() == 0);
}
TEST_END

//------------------------TEST-----------------------------
TEST_START(free_1, TEST_FINISH, DEFAULT_MAX_TIME)
{
	TEST_ASSERT(heap_setup() == 0)
	
	// Zwalnianie wskaźników zwróconych przez malloc, calloc, realloc nie może powodować błędów
	for(int i=1; i<10; i++)
	{
		void *ptr1 = malloc(50*i);
		void *ptr2 = calloc(25, 4*i);
		void *ptr3 = realloc(NULL, 50);

		void *ptr4 = malloc_aligned(50);
		void *ptr5 = malloc(100*i);
		void *ptr6 = realloc_aligned(NULL, 50*i);
		
		free(ptr2);
		TEST_ASSERT(heap_validate() == 0);
		free(ptr1);
		free(ptr3);

		free(ptr4);
		free(ptr5);
		free(ptr6);
	}
	
	// Zwalnianie NULL nie może powodować błędu
	free(NULL);
	
	// Podwójne zwalnianie oraz przekazywanie niepoprawnych wskaźników nie powoduje błędu (w tym konkretnym alokatorze)
	void *ptr1 = malloc(50);
	free(ptr1);
	free(ptr1);
	free((uint8_t *)ptr1+1);

	TEST_ASSERT(heap_validate() == 0);
}
TEST_END

//------------------------TEST-----------------------------
TEST_START(malloc_aligned_1, TEST_FINISH, DEFAULT_MAX_TIME)
{
	TEST_ASSERT(heap_setup() == 0)
	
	// Alokowanie zera bajtów zwraca NULL
	TEST_ASSERT(malloc_aligned(0) ==  NULL);
	
	// Alokowanie obszaru gdy dostępna jest pamięć zwraca wskaźnik wyrównany do strony
	for(int i=1; i<50; i++)
	{
		void *ptr = malloc_aligned(500*i);
		TEST_ASSERT(ptr != NULL);
		TEST_ASSERT(is_aligned(ptr, PAGE_SIZE));
	}
	
	TEST_ASSERT(heap_validate() == 0);
}
TEST_END

//------------------------TEST-----------------------------
TEST_START(malloc_aligned_2, TEST_FINISH, DEFAULT_MAX_TIME)
{
	// Alokowanie obszaru gdy nie ma wystarczająco pamięci powinno zwracać NULL
	set_mem_limit(PAGE_SIZE);
	TEST_ASSERT(heap_setup() == 0)
	TEST_ASSERT(malloc_aligned(10000) == NULL);
	
	TEST_ASSERT(heap_validate() == 0);
}
TEST_END

//------------------------TEST-----------------------------
TEST_START(calloc_aligned_1, TEST_FINISH, DEFAULT_MAX_TIME)
{
	TEST_ASSERT(heap_setup() == 0)
	
	// Alokowanie zera bajtów zwraca NULL
	TEST_ASSERT(calloc_aligned(0, 5) ==  NULL);
	TEST_ASSERT(calloc_aligned(5, 0) ==  NULL);
	
	// Alokowanie obszaru gdy dostępna jest pamięć zwraca wskaźnik wyrównany do strony z wyzerowaną pamięcią
	for(int j=1; j<100; j++)
	{
		uint8_t *ptr = (uint8_t *)calloc_aligned(50, 8*j);
		TEST_ASSERT(ptr != NULL);
		TEST_ASSERT(is_aligned(ptr, PAGE_SIZE));
		for(int i=0; i<50*8*j; i++)
			TEST_ASSERT(ptr[i] == 0);
	}
		
	// Podczas przepełnienia zwracany jest NULL
	size_t max = -1;
	TEST_ASSERT(calloc_aligned(max, 2) == NULL);
	
	TEST_ASSERT(heap_validate() == 0);
}
TEST_END

//------------------------TEST-----------------------------
TEST_START(calloc_aligned_2, TEST_FINISH, DEFAULT_MAX_TIME)
{
	// Próba alokowania obszaru gdy nie ma wystarczająco pamięci zwraca NULL
	set_mem_limit(PAGE_SIZE);
	TEST_ASSERT(heap_setup() == 0)
	TEST_ASSERT(calloc_aligned(10000, 8) == NULL);
	
	TEST_ASSERT(heap_validate() == 0);
}
TEST_END

//------------------------TEST-----------------------------
TEST_START(get_free_space, TEST_FINISH, DEFAULT_MAX_TIME)
{
	// Gdy stos nie jest zainicjowany funkcja zwraca 0
	TEST_ASSERT(heap_get_free_space() == 0);
	
	TEST_ASSERT(heap_setup() == 0);
	
	// Wykonujemy sekwencji operacji na stercie i śledzimy wolną pamięć
	size_t size1 = heap_get_free_space();
	void *ptr1 = malloc(100);
	size_t size2 = heap_get_free_space();
	void *ptr2 = malloc(50);
	size_t size3 = heap_get_free_space();
	free(ptr1);
	size_t size4 = heap_get_free_space();
	free(ptr2);
	size_t size5 = heap_get_free_space();
	
	// Relacje pomiędzy rozmiarami muszą się zgadzać
	TEST_ASSERT(size1 > size2 && size2 > size3 && size3 < size4 && size4 < size5);
	
	// Rozmiar wolnego miejsca na początku i na końcu musi być identyczny
	TEST_ASSERT(size1 == size5);
	
	TEST_ASSERT(heap_validate() == 0);
}
TEST_END

//------------------------TEST-----------------------------
TEST_START(get_used_space, TEST_FINISH, DEFAULT_MAX_TIME)
{
	// Gdy stos nie jest zainicjowany funkcja zwraca 0
	TEST_ASSERT(heap_get_used_space() == 0);
	
	TEST_ASSERT(heap_setup() == 0);
	
	// Wykonujemy sekwencji operacji na stercie i śledzimy używaną pamięć
	size_t size1 = heap_get_used_space();
	void *ptr1 = malloc(100);
	size_t size2 = heap_get_used_space();
	void *ptr2 = malloc(50);
	size_t size3 = heap_get_used_space();
	free(ptr1);
	size_t size4 = heap_get_used_space();
	free(ptr2);
	size_t size5 = heap_get_used_space();
	
	// Rozmiar zajętego miejsca na początku i na końcu musi być równy rozmiarowi dwuch strażników oraz nagłówków wolnego bloku
	TEST_ASSERT(size1 == 3*BLOCK_SIZE);
	TEST_ASSERT(size5 == 3*BLOCK_SIZE);
	
	// Relacje pomiędzy rozmiarami muszą się zgadzać
	TEST_ASSERT(size1 < size2 && size2 < size3 && size3 > size4 && size4 > size5);
	
	TEST_ASSERT(heap_validate() == 0);
}
TEST_END

//------------------------TEST-----------------------------
TEST_START(get_used_blocks_count, TEST_FINISH, DEFAULT_MAX_TIME)
{
	// Gdy stos nie jest zainicjowany funkcja zwraca 0
	TEST_ASSERT(heap_get_used_blocks_count() == 0);
	
	TEST_ASSERT(heap_setup() == 0);
	
	// Alokowanie pamięci funkcjami malloc, calloc, realloc i śledzenie liczby bloków
	TEST_ASSERT(heap_get_used_blocks_count() == 0);
	void *ptr1 = malloc(100);
	TEST_ASSERT(heap_get_used_blocks_count() == 1);
	void *ptr2 = realloc(ptr1, 200);
	TEST_ASSERT(heap_get_used_blocks_count() == 1);
	void *ptr3 = calloc(4, 50);
	TEST_ASSERT(heap_get_used_blocks_count() == 2);
	free(ptr2);
	TEST_ASSERT(heap_get_used_blocks_count() == 1);
	free(ptr3);
	TEST_ASSERT(heap_get_used_blocks_count() == 0);
	
	TEST_ASSERT(heap_validate() == 0);
}
TEST_END

//------------------------TEST-----------------------------
TEST_START(get_free_gaps_count, TEST_FINISH, DEFAULT_MAX_TIME)
{
	// Gdy stos nie jest zainicjowany funkcja zwraca 0
	TEST_ASSERT(heap_get_free_gaps_count() == 0);
	
	TEST_ASSERT(heap_setup() == 0);
	
	// Alokowanie i zwalnianie pamięci przy śledzeniu liczby bloków
	TEST_ASSERT(heap_get_free_gaps_count() == 1);	
	void *ptr1 = malloc(PAGE_SIZE - 3*BLOCK_SIZE);	
	TEST_ASSERT(heap_get_free_gaps_count() == 0);	
	void *ptr2 = malloc(PAGE_SIZE - BLOCK_SIZE);	
	TEST_ASSERT(heap_get_free_gaps_count() == 0);	
	void *ptr3 = malloc(1);	
	TEST_ASSERT(heap_get_free_gaps_count() == 1);	
	free(ptr2);
	TEST_ASSERT(heap_get_free_gaps_count() == 2);	
	free(ptr1);
	TEST_ASSERT(heap_get_free_gaps_count() == 2);	
	free(ptr3);
	TEST_ASSERT(heap_get_free_gaps_count() == 1);	
	
	TEST_ASSERT(heap_validate() == 0);
}
TEST_END

//------------------------TEST-----------------------------
TEST_START(get_largest_free_area, TEST_FINISH, DEFAULT_MAX_TIME)
{
	// Gdy stos nie jest zainicjowany funkcja zwraca 0
	TEST_ASSERT(heap_get_largest_free_area() == 0);
	
	TEST_ASSERT(heap_setup() == 0);
	
	// Na początku alokator powinien posiadać wolny blok rozmiaru (PAGE_SIZE-3*BLOCK_SIZE)
	size_t size1 = heap_get_largest_free_area();
	TEST_ASSERT(size1 == PAGE_SIZE - 3*BLOCK_SIZE);
	
	// Po zaalokowaniu całego wolnego obszaru, wolny obszar powinien wynosić 0
	int *ptr1 = malloc(size1);
	TEST_ASSERT(heap_get_largest_free_area() == 0);
	
	// Po niewielkiej alokacji powinien powstać wolny obszar, bo alokator zażądał kolejnej strony od systemu i wykorzystał jedynie jej fragment
	int *ptr2 = malloc(1);
	TEST_ASSERT(heap_get_largest_free_area() != 0);
	
	// Po zwolnieniu zaalokowanych obszarów stan największy wolny blok powinien mieć taki rozmiar jak na początku
	free(ptr1);
	free(ptr2);
	TEST_ASSERT(heap_get_largest_free_area() == PAGE_SIZE - 3*BLOCK_SIZE)
	
	TEST_ASSERT(heap_validate() == 0);
}
TEST_END

//------------------------TEST-----------------------------
TEST_START(get_largest_used_block_size, TEST_FINISH, DEFAULT_MAX_TIME)
{
	// Gdy stos nie jest zainicjowany funkcja zwraca 0
	TEST_ASSERT(heap_get_largest_used_block_size() == 0);
	
	TEST_ASSERT(heap_setup() == 0);
	
	// Nic nie jest zaalokowane więc funkcja powinna zwrócić 0
	TEST_ASSERT(heap_get_largest_used_block_size() == 0);
	
	// Jedyny zaalokowany obszar powinien być największym
	int *ptr1 = malloc(400);
	TEST_ASSERT(heap_get_largest_used_block_size() == 400);
	
	// Największy zaalokowany obszar nie powinien się zmienić
	int *ptr2 = malloc(200);
	TEST_ASSERT(heap_get_largest_used_block_size() == 400);
	
	// Po zwolnieniu bloku 400 największy powinien mieć 200
	free(ptr1);
	TEST_ASSERT(heap_get_largest_used_block_size() == 200);
	
	// Wszystkie bloki zostały zwolnine, więc największy powinien mieć 0
	free(ptr2);
	TEST_ASSERT(heap_get_largest_used_block_size() == 0);
	
	TEST_ASSERT(heap_validate() == 0);
}
TEST_END

//------------------------TEST-----------------------------
TEST_START(get_pointer_type, TEST_FINISH, DEFAULT_MAX_TIME)
{
	// Gdy stos nie jest zainicjowany to funkcja zwraca tylko dwie wartości albo pointer_null albo pointer_out_of_heap
	TEST_ASSERT(get_pointer_type(NULL) == pointer_null);
	TEST_ASSERT(get_pointer_type((void *)1) == pointer_out_of_heap);
	TEST_ASSERT(get_pointer_type((void *)printf) == pointer_out_of_heap);
	
	TEST_ASSERT(heap_setup() == 0);
	
	uint8_t *ptr = (uint8_t *)malloc(2000);
	
	// Wskaźnik właśnie został zaalokowany więc powinien być poprawny
	TEST_ASSERT(get_pointer_type(ptr) == pointer_valid);
	
	// Przed przydzielonym obszarem powinny znajmować się blok kontrolny
	TEST_ASSERT(get_pointer_type(ptr-1) == pointer_control_block);
	
	// Zaalokowany blok danych ma rozmiar 2000 więc dodając nie więcej niż 1999 powinnyśmy być w środku
	TEST_ASSERT(get_pointer_type(ptr+1) == pointer_inside_data_block);
	TEST_ASSERT(get_pointer_type(ptr+1000) == pointer_inside_data_block);
	TEST_ASSERT(get_pointer_type(ptr+1999) == pointer_inside_data_block);
	
	// Po zwolnieniu bloku ptr ten sam bloku który był poprawny teraz powinien być niezaalokowany
	free(ptr);
	TEST_ASSERT(get_pointer_type(ptr) == pointer_unallocated);
	
	// Chcemy alokować tylko jeden bajt, lecz alokator przydziela bloki o rozmiarze wielokrotności słowa danych, wiec w rzeczywistości blok jest dłuższy
	uint8_t *byte = (uint8_t *)malloc(1);
	TEST_ASSERT(get_pointer_type(byte+1) == pointer_inside_data_block);
	TEST_ASSERT(get_pointer_type(byte+7) == pointer_inside_data_block);
	TEST_ASSERT(get_pointer_type(byte+WORD_LEN) != pointer_inside_data_block);
	
	TEST_ASSERT(heap_validate() == 0);
}
TEST_END

//------------------------TEST-----------------------------
TEST_START(get_data_block_start, TEST_FINISH, DEFAULT_MAX_TIME)
{
	// Dla niezainicjowanej sterty zawsze zwraca NULL
	TEST_ASSERT(heap_get_data_block_start(NULL) == NULL);
	TEST_ASSERT(heap_get_data_block_start((void *)printf) == NULL);
	
	TEST_ASSERT(heap_setup() == 0);
	
	uint8_t *ptr = (uint8_t *)malloc(2000);
	
	// Gdy wskaźnik wskazuje na wnętrze zaalokowanego bloku to funkcja zwraca jego początek
	TEST_ASSERT(heap_get_data_block_start(ptr) == ptr);
	TEST_ASSERT(heap_get_data_block_start(ptr + 1999) == ptr);
	
	// Gdy wskaźnik wskazuje przed albo po zaalokowanym bloku to funkcja zwraca NULL
	TEST_ASSERT(heap_get_data_block_start(ptr - 1) == NULL);
	TEST_ASSERT(heap_get_data_block_start(ptr + 2000) == NULL);
	
	TEST_ASSERT(heap_validate() == 0);
}
TEST_END

//------------------------TEST-----------------------------
TEST_START(get_block_size, TEST_FINISH, DEFAULT_MAX_TIME)
{
	// Dla niezainicjowanej sterty zawsze zwraca NULL
	TEST_ASSERT(heap_get_block_size(NULL) == 0);
	TEST_ASSERT(heap_get_block_size((void *)printf) == 0);
	
	TEST_ASSERT(heap_setup() == 0);
	
	// Rozmiar bloku powinien wynosić 8
	uint8_t *ptr1 = (uint8_t *)malloc(8);
	TEST_ASSERT(heap_get_block_size(ptr1) == 8);
	
	// Gdy wskaźnik nie trafia w blok danych to funkcja zwraca długość bloku 0
	TEST_ASSERT(heap_get_block_size(ptr1-1) == 0);
	TEST_ASSERT(heap_get_block_size(ptr1+8) == 0);
	
	// Chcemy alokować blok długości 1, lecz zostaje on zaokrąglony do 8
	void *ptr2 = malloc(1);
	TEST_ASSERT(heap_get_block_size(ptr2) == 8);
	
	// Chcemy dostać blok długości 100, lecz zostaje on zaokrąglony do 8
	void *ptr3 = realloc(ptr2, 100);
	TEST_ASSERT(heap_get_block_size(ptr2) == 104);
	
	// Gdy zwolnimy zaalokowane obszary to nie będzie już tam bloków danych, czyli długość powinna wynosić 0
	free(ptr1);
	free(ptr3);
	TEST_ASSERT(heap_get_block_size(ptr2) == 0);
	TEST_ASSERT(heap_get_block_size(ptr3) == 0);
	
	TEST_ASSERT(heap_validate() == 0);
}
TEST_END

static void *thread_fun1(void *ptr)
{
	for(int i=0; i<200; i++)
	{
		malloc(40);
		calloc(5, 5);
	}
	return NULL;
}

//------------------------TEST-----------------------------
TEST_START(threads_1, TEST_FINISH, DEFAULT_MAX_TIME)
{
	TEST_ASSERT(heap_setup() == 0);
	
	// Test sprawdzający czy równoległe alokowanie działa bez problemu
	pthread_t thread1, thread2;
	pthread_create(&thread1, NULL, thread_fun1, NULL);
	pthread_create(&thread2, NULL, thread_fun1, NULL);
	
	pthread_join(thread1, NULL);
	pthread_join(thread2, NULL);
	
	TEST_ASSERT(heap_get_used_blocks_count() == 800);
	TEST_ASSERT(heap_validate() == 0);
}
TEST_END

static void *thread_fun2(void *ptr)
{
	for(int i=0; i<200; i++)
	{
		int *ptr = malloc(i);
		free(ptr);
		ptr = malloc_aligned(i);
		free(ptr);
	}
	return NULL;
}

//------------------------TEST-----------------------------
TEST_START(threads_2, TEST_FINISH, DEFAULT_MAX_TIME)
{
	TEST_ASSERT(heap_setup() == 0);

	// Test sprawdzający czy równoległe zwalnianie obszarów działa bez problemu
	pthread_t thread1, thread2;
	pthread_create(&thread1, NULL, thread_fun2, NULL);
	pthread_create(&thread2, NULL, thread_fun2, NULL);

	pthread_join(thread1, NULL);
	pthread_join(thread2, NULL);
	
	TEST_ASSERT(heap_get_used_blocks_count() == 0);
	TEST_ASSERT(heap_get_free_gaps_count() == 1);
	TEST_ASSERT(heap_validate() == 0);
}
TEST_END

static void *thread_fun3(void *ptr)
{
	for(int i=0; i<200; i++)
	{
		int *ptr = malloc(i);
		
		heap_get_used_space();
		heap_get_largest_used_block_size();
		heap_get_used_blocks_count();
		heap_get_free_space();
		heap_get_largest_free_area();
		heap_get_free_gaps_count();
		
		free(ptr);
		
		heap_get_used_space();
		heap_get_largest_used_block_size();
		heap_get_used_blocks_count();
		heap_get_free_space();
		heap_get_largest_free_area();
		heap_get_free_gaps_count();
	}
	return NULL;
}

//------------------------TEST-----------------------------
TEST_START(threads_3, TEST_FINISH, DEFAULT_MAX_TIME)
{
	TEST_ASSERT(heap_setup() == 0);

	// Test sprawdzający czy równoległe pobieranie statystyk stery nie powoduje błędu(nie powoduje przerwania programu / deadlocków)
	pthread_t thread1, thread2;
	pthread_create(&thread1, NULL, thread_fun3, NULL);
	pthread_create(&thread2, NULL, thread_fun3, NULL);

	pthread_join(thread1, NULL);
	pthread_join(thread2, NULL);
	
	TEST_ASSERT(heap_get_used_blocks_count() == 0);
	TEST_ASSERT(heap_get_free_gaps_count() == 1);
	TEST_ASSERT(heap_validate() == 0);
}
TEST_END

static void *thread_fun4(void *ptr)
{
	for(int i=10; i<200; i++)
	{
		char *ptr = (char*)malloc(i);
		
		TEST_ASSERT(get_pointer_type(ptr) == pointer_valid);
		TEST_ASSERT(get_pointer_type(ptr+i-1) == pointer_inside_data_block);
		TEST_ASSERT(get_pointer_type(ptr+1) == pointer_inside_data_block);
		TEST_ASSERT(get_pointer_type(ptr-1) == pointer_control_block);
		
		free(ptr);
	}
	return NULL;
}

//------------------------TEST-----------------------------
TEST_START(threads_4, TEST_FINISH, DEFAULT_MAX_TIME)
{
	TEST_ASSERT(heap_setup() == 0);

	// Test sprawdzający równoległe działanie funkcji get_pointer_type, heap_get_data_block_start, heap_get_block_size
	pthread_t thread1, thread2;
	pthread_create(&thread1, NULL, thread_fun4, NULL);
	pthread_create(&thread2, NULL, thread_fun4, NULL);

	pthread_join(thread1, NULL);
	pthread_join(thread2, NULL);
	
	TEST_ASSERT(heap_get_used_blocks_count() == 0);
	TEST_ASSERT(heap_get_free_gaps_count() == 1);
	TEST_ASSERT(heap_validate() == 0);
}
TEST_END

//------------------------TESTS-SET-----------------------------
SET_START(heap_tests)
{
	SET_ADD(heap_setup_1);
	SET_ADD(heap_setup_2);
	
	SET_ADD(malloc_1);
	SET_ADD(malloc_2);
	
	SET_ADD(calloc_1);
	SET_ADD(calloc_2);
	
	SET_ADD(realloc_1);
	SET_ADD(realloc_2);
	
	SET_ADD(free_1);
	
	SET_ADD(malloc_aligned_1);
	SET_ADD(malloc_aligned_2);
	
	SET_ADD(calloc_aligned_1);
	SET_ADD(calloc_aligned_2);
	
	SET_ADD(get_free_space);
	SET_ADD(get_used_space);
	
	SET_ADD(get_used_blocks_count);
	SET_ADD(get_free_gaps_count);
	
	SET_ADD(get_largest_free_area);
	SET_ADD(get_largest_used_block_size);
	
	SET_ADD(get_pointer_type);
	SET_ADD(get_data_block_start);
	SET_ADD(get_block_size);
	
	SET_ADD(threads_1);
	SET_ADD(threads_2);
	SET_ADD(threads_3);
	SET_ADD(threads_4);
}
SET_END


int main(void)
{	
	SET_RUN(heap_tests);
	return 0;
}
