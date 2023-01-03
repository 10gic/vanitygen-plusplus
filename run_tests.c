#include "tests.h"
#include <check.h>
#include <stdio.h>

int GRSFlag = 0; // avoid link error when test function in util.c
int TRXFlag = 0; // avoid link error when test function in util.c

// run suite
//
// See:
// https://libcheck.github.io/check/
// http://developertesting.rocks/tools/check/
int main(void)
{
    int number_failed;
    Suite* suite = create_sample_suite();
    SRunner* runner = srunner_create(suite);
    // srunner_add_suite(runner, <another suite would go here>);

    srunner_run_all(runner, CK_VERBOSE);
    number_failed = srunner_ntests_failed(runner);
    srunner_free(runner);
    if (number_failed == 0) {
        printf("PASSED ALL TESTS\n");
    }
    return number_failed;
}
