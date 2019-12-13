#ifndef __TESTS_H__
#define __TESTS_H__

#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include "colors.h"


void timer_handler(union sigval sv);


#define TEST_NOT_FINISH 0
#define TEST_FINISH 	1


#define TEST_START(__TEST_NAME, __SHOULD_FINISH, __MAX_NANO_TIME)\
int unit_test_##__TEST_NAME(void)\
{\
	char *test_name = #__TEST_NAME;\
	int should_finish = __SHOULD_FINISH;\
	printf(COLOR_CYAN "TEST %s started\n" COLOR_RESET, test_name);\
	int pid = fork();\
	if(pid == 0)\
	{\
		timer_t timer_id;\
		struct itimerspec ts;\
		struct sigevent se;\
		\
		se.sigev_notify = SIGEV_THREAD;\
		se.sigev_notify_function = timer_handler;\
		se.sigev_notify_attributes = NULL;\
		se.sigev_signo = 7;\
		\
		ts.it_value.tv_sec = __MAX_NANO_TIME / 1000000000;\
		ts.it_value.tv_nsec = __MAX_NANO_TIME % 1000000000;\
		ts.it_interval.tv_sec = 0;\
		ts.it_interval.tv_nsec = 0;\
		\
		timer_create(CLOCK_REALTIME, &se, &timer_id);\
		timer_settime(timer_id, 0, &ts, 0);
			

#define TEST_END\
		exit(0);\
	}\
	else\
	{\
		int status;\
		waitpid(pid, &status, 0);\
		int return_code = WEXITSTATUS(status);\
		int finished =  WIFEXITED(status);\
		if(finished != should_finish)\
		{\
			if(should_finish == TEST_NOT_FINISH)\
				printf(COLOR_RED "Test %s failed: finished(should not finish)\n" COLOR_RESET, test_name);\
			else\
				printf(COLOR_RED "Test %s failed: not finished(should finish)\n" COLOR_RESET, test_name);\
			return 0;\
		}\
		else if(return_code == 2)\
		{\
			printf(COLOR_RED "Test %s failed: time expired\n" COLOR_RESET, test_name);\
			return 0;\
		}\
		else if(return_code != 0)\
		{\
			printf(COLOR_RED "Test %s failed: assertion failed(look above)\n" COLOR_RESET, test_name);\
			return 0;\
		}\
		else\
		{\
			printf(COLOR_GREEN "Test %s passed\n" COLOR_RESET, test_name);\
			return 1;\
		}\
	}\
}


#define TEST_ASSERT(__BOOL) \
if(!(__BOOL)) \
{\
	printf(COLOR_RED "ASSERTION_FAILED: LINE %d TEST_ASSERT(" #__BOOL ")\n" COLOR_RESET, __LINE__);\
	exit(1);\
}


#define SET_START(__NAME)\
void tests_set_##__NAME(void)\
{\
	int total_count = 0;\
	int success_count = 0;
	
	
#define SET_END \
printf(COLOR_CYAN "Overall Result: %d/%d\n" COLOR_RESET, success_count, total_count);\
}
	


#define SET_ADD(__NAME)\
{\
	int temp = TEST_RUN(__NAME);\
	if(temp) success_count++;\
	total_count++;\
}


#define TEST_RUN(__NAME) unit_test_##__NAME()
#define SET_RUN(__NAME) tests_set_##__NAME()


#endif