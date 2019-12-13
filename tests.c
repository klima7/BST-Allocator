#include <signal.h>
#include <stdlib.h>
#include "tests.h"

void timer_handler(union sigval sv) 
{
	exit(2);
}

