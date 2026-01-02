/* Unity Test Framework - Minimal Implementation */
#include "unity.h"

int Unity_TestsRun = 0;
int Unity_TestsFailed = 0;
static const char* Unity_TestFile = NULL;

void UnityBegin(const char* filename) {
    Unity_TestsRun = 0;
    Unity_TestsFailed = 0;
    Unity_TestFile = filename;
    printf("\n=================================\n");
    printf("Running tests from: %s\n", filename);
    printf("=================================\n");
}

int UnityEnd(void) {
    printf("\n---------------------------------\n");
    if (Unity_TestsFailed == 0) {
        printf("ALL TESTS PASSED (%d/%d)\n", Unity_TestsRun, Unity_TestsRun);
        printf("OK\n");
    } else {
        printf("SOME TESTS FAILED (%d/%d failed)\n", Unity_TestsFailed, Unity_TestsRun);
        printf("FAILED\n");
    }
    printf("---------------------------------\n\n");
    return Unity_TestsFailed;
}

void UnityDefaultTestRun(void (*Func)(void), const char* FuncName, const int FuncLineNum) {
    int failed_before = Unity_TestsFailed;
    Unity_TestsRun++;

    printf("TEST %d: %s", Unity_TestsRun, FuncName);

    if (Func) {
        Func();
    }

    if (Unity_TestsFailed == failed_before) {
        printf(" ... PASS\n");
    } else {
        printf(" ... FAIL\n");
    }
}
