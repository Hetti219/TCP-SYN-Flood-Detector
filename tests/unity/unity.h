/* Unity Test Framework - Minimal Header */
#ifndef UNITY_FRAMEWORK_H
#define UNITY_FRAMEWORK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Test result tracking */
extern int Unity_TestsRun;
extern int Unity_TestsFailed;

/* Test assertion macros */
#define TEST_ASSERT(condition) \
    do { if (!(condition)) { \
        printf("FAIL: %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        Unity_TestsFailed++; \
    }} while(0)

#define TEST_ASSERT_TRUE(condition) TEST_ASSERT(condition)
#define TEST_ASSERT_FALSE(condition) TEST_ASSERT(!(condition))
#define TEST_ASSERT_EQUAL(expected, actual) TEST_ASSERT((expected) == (actual))
#define TEST_ASSERT_NOT_EQUAL(expected, actual) TEST_ASSERT((expected) != (actual))
#define TEST_ASSERT_EQUAL_INT(expected, actual) TEST_ASSERT((expected) == (actual))
#define TEST_ASSERT_EQUAL_UINT8(expected, actual) TEST_ASSERT((expected) == (actual))
#define TEST_ASSERT_EQUAL_UINT32(expected, actual) TEST_ASSERT((expected) == (actual))
#define TEST_ASSERT_EQUAL_UINT64(expected, actual) TEST_ASSERT((expected) == (actual))
#define TEST_ASSERT_EQUAL_STRING(expected, actual) TEST_ASSERT(strcmp(expected, actual) == 0)
#define TEST_ASSERT_NULL(pointer) TEST_ASSERT((pointer) == NULL)
#define TEST_ASSERT_NOT_NULL(pointer) TEST_ASSERT((pointer) != NULL)
#define TEST_ASSERT_GREATER_THAN(threshold, actual) TEST_ASSERT((actual) > (threshold))
#define TEST_ASSERT_LESS_THAN(threshold, actual) TEST_ASSERT((actual) < (threshold))
#define TEST_ASSERT_GREATER_OR_EQUAL(threshold, actual) TEST_ASSERT((actual) >= (threshold))
#define TEST_ASSERT_EQUAL_PTR(expected, actual) TEST_ASSERT((expected) == (actual))

/* Test pass macro - test passes by default if no assertions fail */
#define TEST_PASS() do { } while(0)

/* Test framework functions */
void UnityBegin(const char* filename);
int UnityEnd(void);
void UnityDefaultTestRun(void (*Func)(void), const char* FuncName, const int FuncLineNum);

/* Test runner macros */
#define RUN_TEST(func) UnityDefaultTestRun(func, #func, __LINE__)
#define TEST_CASE(name) void name(void)

#endif /* UNITY_FRAMEWORK_H */
