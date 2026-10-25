#include <stdlib.h>
#include <stdio.h>
#include "harness/unity.h"
#include "../src/lab.h"

void setUp(void)
{
  printf("Setting up tests...\n");
}

void tearDown(void)
{
  printf("Tearing down tests...\n");
}

int main(void)
{
  UNITY_BEGIN();
  return UNITY_END();
}
