#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

/* ------------------------------------------------------------------------
 * Task 1 Tests - Address Parsing & Formatting
 * --------------------------------------------------------------------- */

static void test_ip_parse(void)
{
  uint32_t addr = 0;

  // Valid IPs
  TEST_ASSERT_TRUE(ip_parse("0.0.0.0", &addr));
  TEST_ASSERT_EQUAL_HEX32(0x00000000, addr);

  TEST_ASSERT_TRUE(ip_parse("192.168.1.10", &addr));
  TEST_ASSERT_EQUAL_HEX32(0xC0A8010A, addr);

  TEST_ASSERT_TRUE(ip_parse("255.255.255.255", &addr));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFF, addr);

  // Invalid IPs
  TEST_ASSERT_FALSE(ip_parse(NULL, &addr));
  TEST_ASSERT_FALSE(ip_parse("192.168.1", &addr));       // Too few octets
  TEST_ASSERT_FALSE(ip_parse("192.168.1.10.5", &addr));  // Too many octets
  TEST_ASSERT_FALSE(ip_parse("192.168.01.10", &addr));   // Leading zero in octet
  TEST_ASSERT_FALSE(ip_parse("192.168.256.1", &addr));   // Octet > 255
  TEST_ASSERT_FALSE(ip_parse("192.168.1.10a", &addr));   // Trailing invalid char
  TEST_ASSERT_FALSE(ip_parse("abc.def.ghi.jkl", &addr)); // Non-digits
  TEST_ASSERT_FALSE(ip_parse("x.0.0.0", &addr));         // Invalid first character in an octet
  TEST_ASSERT_FALSE(ip_parse("192..1.10", &addr));       // Missing octet / double dot
}

static void test_ip_format(void)
{
  char out[IP_STR_LEN];

  ip_format(0xC0A8010A, out);
  TEST_ASSERT_EQUAL_STRING("192.168.1.10", out);

  ip_format(0x00000000, out);
  TEST_ASSERT_EQUAL_STRING("0.0.0.0", out);

  ip_format(0xFFFFFFFF, out);
  TEST_ASSERT_EQUAL_STRING("255.255.255.255", out);
}

static void test_cidr_parse(void)
{
  cidr_t block;

  // Valid CIDR
  TEST_ASSERT_TRUE(cidr_parse("192.168.1.0/24", &block));
  TEST_ASSERT_EQUAL_HEX32(0xC0A80100, block.addr);
  TEST_ASSERT_EQUAL_UINT8(24, block.prefix);

  TEST_ASSERT_TRUE(cidr_parse("10.0.0.0/0", &block));
  TEST_ASSERT_EQUAL_UINT8(0, block.prefix);

  TEST_ASSERT_TRUE(cidr_parse("1.2.3.4/32", &block));
  TEST_ASSERT_EQUAL_UINT8(32, block.prefix);

  // Invalid CIDR
  TEST_ASSERT_FALSE(cidr_parse(NULL, &block));
  TEST_ASSERT_FALSE(cidr_parse("192.168.1.0", &block));        // Missing slash/prefix
  TEST_ASSERT_FALSE(cidr_parse("192.168.1.0//24", &block));    // Multiple slashes
  TEST_ASSERT_FALSE(cidr_parse("/24", &block));                // Missing IP
  TEST_ASSERT_FALSE(cidr_parse("192.168.1.0/33", &block));     // Prefix > 32
  TEST_ASSERT_FALSE(cidr_parse("192.168.1.0/01", &block));     // Leading zero in prefix
  TEST_ASSERT_FALSE(cidr_parse("999.999.999.999/24", &block)); // Bad IP part
}

static void test_cidr_format(void)
{
  char out[CIDR_STR_LEN];
  cidr_t block = {.addr = 0xC0A80100, .prefix = 24};

  cidr_format(block, out);
  TEST_ASSERT_EQUAL_STRING("192.168.1.0/24", out);

  // Prefix bound check (>32 clamped)
  block.prefix = 40;
  cidr_format(block, out);
  TEST_ASSERT_EQUAL_STRING("192.168.1.0/32", out);
}

/* ------------------------------------------------------------------------
 * Task 2 Tests - Subnet Arithmetic
 * --------------------------------------------------------------------- */

static void test_cidr_mask(void)
{
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFF00, cidr_mask(24));
  TEST_ASSERT_EQUAL_HEX32(0x00000000, cidr_mask(0));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFF, cidr_mask(32));
  TEST_ASSERT_EQUAL_HEX32(0xFFFFFFFF, cidr_mask(40)); // > 32 clamped
}

static void test_cidr_network_broadcast(void)
{
  cidr_t block = {.addr = 0xC0A80145, .prefix = 24}; // 192.168.1.69/24

  TEST_ASSERT_EQUAL_HEX32(0xC0A80100, cidr_network(block));
  TEST_ASSERT_EQUAL_HEX32(0xC0A801FF, cidr_broadcast(block));

  // Edge case /32
  cidr_t host_block = {.addr = 0x0A000001, .prefix = 32};
  TEST_ASSERT_EQUAL_HEX32(0x0A000001, cidr_network(host_block));
  TEST_ASSERT_EQUAL_HEX32(0x0A000001, cidr_broadcast(host_block));
}

static void test_cidr_hosts(void)
{
  cidr_t b24 = {.addr = 0xC0A80100, .prefix = 24};
  TEST_ASSERT_EQUAL_HEX32(0xC0A80101, cidr_first_host(b24));
  TEST_ASSERT_EQUAL_HEX32(0xC0A801FE, cidr_last_host(b24));
  TEST_ASSERT_EQUAL_UINT64(254, cidr_host_count(b24));

  // /31 point-to-point RFC 3021
  cidr_t b31 = {.addr = 0xC0A80100, .prefix = 31};
  TEST_ASSERT_EQUAL_HEX32(0xC0A80100, cidr_first_host(b31));
  TEST_ASSERT_EQUAL_HEX32(0xC0A80101, cidr_last_host(b31));
  TEST_ASSERT_EQUAL_UINT64(2, cidr_host_count(b31));

  // /32 single host
  cidr_t b32 = {.addr = 0xC0A80101, .prefix = 32};
  TEST_ASSERT_EQUAL_HEX32(0xC0A80101, cidr_first_host(b32));
  TEST_ASSERT_EQUAL_HEX32(0xC0A80101, cidr_last_host(b32));
  TEST_ASSERT_EQUAL_UINT64(1, cidr_host_count(b32));

  // /0 special case host count
  cidr_t b0 = {.addr = 0x00000000, .prefix = 0};
  TEST_ASSERT_EQUAL_UINT64(4294967294ULL, cidr_host_count(b0));
}

static void test_cidr_contains_and_is_network(void)
{
  cidr_t block = {.addr = 0xC0A80100, .prefix = 24};

  TEST_ASSERT_TRUE(cidr_is_network(block));

  cidr_t non_net = {.addr = 0xC0A8010A, .prefix = 24};
  TEST_ASSERT_FALSE(cidr_is_network(non_net));

  TEST_ASSERT_TRUE(cidr_contains(block, 0xC0A80100));
  TEST_ASSERT_TRUE(cidr_contains(block, 0xC0A801FF));
  TEST_ASSERT_FALSE(cidr_contains(block, 0xC0A80200));
}

static void test_cidr_subnet(void)
{
  cidr_t block = {.addr = 0xC0A80100, .prefix = 24};
  cidr_t non_net = {.addr = 0xC0A8010A, .prefix = 24};
  cidr_t out;

  // Valid subnet split (/24 into 4 subnets -> /26)
  TEST_ASSERT_TRUE(cidr_subnet(block, 4, 0, &out));
  TEST_ASSERT_EQUAL_HEX32(0xC0A80100, out.addr);
  TEST_ASSERT_EQUAL_UINT8(26, out.prefix);

  TEST_ASSERT_TRUE(cidr_subnet(block, 4, 3, &out));
  TEST_ASSERT_EQUAL_HEX32(0xC0A801C0, out.addr);
  TEST_ASSERT_EQUAL_UINT8(26, out.prefix);

  // Invalid subnet cases
  TEST_ASSERT_FALSE(cidr_subnet(block, 4, 0, NULL));   // out is NULL
  TEST_ASSERT_FALSE(cidr_subnet(block, 0, 0, &out));   // n == 0
  TEST_ASSERT_FALSE(cidr_subnet(non_net, 4, 0, &out)); // block not network
  TEST_ASSERT_FALSE(cidr_subnet(block, 3, 0, &out));   // n not power of two
  TEST_ASSERT_FALSE(cidr_subnet(block, 4, 4, &out));   // i out of range

  cidr_t b32 = {.addr = 0x0A000001, .prefix = 32};
  TEST_ASSERT_FALSE(cidr_subnet(b32, 2, 0, &out)); // prefix exceeds 32
}

/* ------------------------------------------------------------------------
 * Task 3 Tests - Longest Prefix Match & Forwarding Tables
 * --------------------------------------------------------------------- */

static void test_route_parse(void)
{
  route_t r;

  // Valid route lines
  TEST_ASSERT_TRUE(route_parse("192.168.1.0/24 10.0.0.1 eth0", &r));
  TEST_ASSERT_EQUAL_HEX32(0xC0A80100, r.dest.addr);
  TEST_ASSERT_EQUAL_UINT8(24, r.dest.prefix);
  TEST_ASSERT_EQUAL_HEX32(0x0A000001, r.gateway);
  TEST_ASSERT_EQUAL_STRING("eth0", r.dev);

  // Default route and direct gateway
  TEST_ASSERT_TRUE(route_parse("default direct eth1", &r));
  TEST_ASSERT_EQUAL_HEX32(0x00000000, r.dest.addr);
  TEST_ASSERT_EQUAL_UINT8(0, r.dest.prefix);
  TEST_ASSERT_EQUAL_UINT32(0, r.gateway);
  TEST_ASSERT_EQUAL_STRING("eth1", r.dev);

  // Invalid route lines
  TEST_ASSERT_FALSE(route_parse(NULL, &r));
  TEST_ASSERT_FALSE(route_parse("   ", &r));                                    // Empty/whitespace only
  TEST_ASSERT_FALSE(route_parse("192.168.1.5/24 10.0.0.1 eth0", &r));           // host bits set in dest
  TEST_ASSERT_FALSE(route_parse("192.168.1.0/24 bad_gateway eth0", &r));        // bad gateway
  TEST_ASSERT_FALSE(route_parse("192.168.1.0/24 direct", &r));                  // missing device field
  TEST_ASSERT_FALSE(route_parse("192.168.1.0/24 direct eth0 extra_field", &r)); // too many fields
  TEST_ASSERT_FALSE(route_parse("192.168.1.0/24 direct eth invalid", &r));      // whitespace inside device name
  TEST_ASSERT_FALSE(route_parse("192.168.1.0/24 direct eth0\rname", &r));       // control whitespace inside device name
}

static void test_fwd_table_operations(void)
{
  fwd_table_t *table = table_create();
  TEST_ASSERT_NOT_NULL(table);
  TEST_ASSERT_EQUAL_INT(0, table_count(table));

  route_t r1 = {.dest = {0xC0A80100, 24}, .gateway = 0x0A000001, .dev = "eth0"};
  route_t r2 = {.dest = {0xC0A80000, 16}, .gateway = 0x0A000002, .dev = "eth1"};
  route_t r_default = {.dest = {0x00000000, 0}, .gateway = 0x0A000003, .dev = "eth2"};

  // Invalid table adds
  TEST_ASSERT_FALSE(table_add(NULL, &r1));
  TEST_ASSERT_FALSE(table_add(table, NULL));

  route_t bad_dest_route = {.dest = {0xC0A80105, 24}, .gateway = 0x0A000001, .dev = "eth0"};
  TEST_ASSERT_FALSE(table_add(table, &bad_dest_route)); // Non-zero host bits in dest

  // Valid adds
  TEST_ASSERT_TRUE(table_add(table, &r1));
  TEST_ASSERT_EQUAL_INT(1, table_count(table));

  // Duplicate add should fail
  TEST_ASSERT_FALSE(table_add(table, &r1));

  TEST_ASSERT_TRUE(table_add(table, &r2));
  TEST_ASSERT_TRUE(table_add(table, &r_default));
  TEST_ASSERT_EQUAL_INT(3, table_count(table));

  // Test capacity expansion by adding multiple routes to trigger realloc block
  for (int i = 1; i <= 10; i++)
  {
    route_t extra_r = {.dest = {(uint32_t)(0x0A000000 + (i << 16)), 16}, .gateway = 0, .dev = "eth3"};
    // Ensure network address representation is valid
    extra_r.dest.addr &= cidr_mask(extra_r.dest.prefix);
    // Avoid duplicate if i collides
    (void)table_add(table, &extra_r);
  }

  // Test Longest Prefix Match (table_lookup)
  const route_t *matched = table_lookup(table, 0xC0A8010A);
  TEST_ASSERT_NOT_NULL(matched);
  TEST_ASSERT_EQUAL_STRING("eth0", matched->dev);

  matched = table_lookup(table, 0xC0A80501);
  TEST_ASSERT_NOT_NULL(matched);
  TEST_ASSERT_EQUAL_STRING("eth1", matched->dev);

  matched = table_lookup(table, 0x7F000001);
  TEST_ASSERT_NOT_NULL(matched);
  TEST_ASSERT_EQUAL_STRING("eth2", matched->dev);

  // NULL table lookup
  TEST_ASSERT_NULL(table_lookup(NULL, 0xC0A8010A));

  // Test table_load and error handling
  fwd_table_t *loaded_table = table_create();
  size_t bad_line = 0;

  FILE *tmp = tmpfile();
  TEST_ASSERT_NOT_NULL(tmp);
  fprintf(tmp, "# Comment line\n");
  fprintf(tmp, "  \n"); // Blank line
  fprintf(tmp, "10.0.0.0/8 direct eth3\n");
  rewind(tmp);
  TEST_ASSERT_TRUE(table_load(loaded_table, tmp, &bad_line));
  TEST_ASSERT_EQUAL_INT(0, bad_line);
  TEST_ASSERT_EQUAL_INT(1, table_count(loaded_table));
  fclose(tmp);

  // Test table_load with invalid file / arguments
  TEST_ASSERT_FALSE(table_load(NULL, NULL, &bad_line));
  TEST_ASSERT_FALSE(table_load(loaded_table, NULL, &bad_line));

  // Test table_load with bad route line tracking
  FILE *bad_tmp = tmpfile();
  fprintf(bad_tmp, "192.168.1.0/24 10.0.0.1 eth0\n");
  fprintf(bad_tmp, "malformed_line_here\n");
  rewind(bad_tmp);

  size_t failed_line_num = 0;
  TEST_ASSERT_FALSE(table_load(loaded_table, bad_tmp, &failed_line_num));
  TEST_ASSERT_EQUAL_INT(2, failed_line_num);
  fclose(bad_tmp);

  // A directory stream fails when getline attempts to read it.
  FILE *error_stream = fopen(".", "r");
  TEST_ASSERT_NOT_NULL(error_stream);
  size_t io_error_line = 1;
  TEST_ASSERT_FALSE(table_load(loaded_table, error_stream, &io_error_line));
  TEST_ASSERT_EQUAL_INT(0, io_error_line);
  TEST_ASSERT_TRUE(ferror(error_stream));
  fclose(error_stream);

  // Clean up
  table_destroy(table);
  table_destroy(loaded_table);
  table_destroy(NULL); // Should safely handle NULL
}

/* ------------------------------------------------------------------------
 * Main Runner
 * --------------------------------------------------------------------- */

int main(void)
{
  UNITY_BEGIN();

  // Task 1
  RUN_TEST(test_ip_parse);
  RUN_TEST(test_ip_format);
  RUN_TEST(test_cidr_parse);
  RUN_TEST(test_cidr_format);

  // Task 2
  RUN_TEST(test_cidr_mask);
  RUN_TEST(test_cidr_network_broadcast);
  RUN_TEST(test_cidr_hosts);
  RUN_TEST(test_cidr_contains_and_is_network);
  RUN_TEST(test_cidr_subnet);

  // Task 3
  RUN_TEST(test_route_parse);
  RUN_TEST(test_fwd_table_operations);

  return UNITY_END();
}