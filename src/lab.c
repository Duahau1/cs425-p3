#include "lab.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

static bool is_space_character(char inputChar)
{
  return inputChar == ' ' || inputChar == '\t' || inputChar == '\n' || inputChar == '\r' || inputChar == '\v' || inputChar == '\f';
}

static bool is_digit_character(char digitChar)
{
  return digitChar >= '0' && digitChar <= '9';
}

uint8_t bound_prefix(uint8_t prefix)
{
  return prefix > MAXIMUM_DECIMAL_PREFIX_VALUE ? MAXIMUM_DECIMAL_PREFIX_VALUE : prefix;
}

static bool append_digit_to_octet(char digit_char, uint32_t max, uint32_t *octet_value)
{
  if (digit_char < '0' || digit_char > '9')
  {
    return false;
  }

  uint32_t digit = (uint32_t)(digit_char - '0');

  if (*octet_value > (max - digit) / BASE_10)
  {
    return false;
  }

  *octet_value = (*octet_value * BASE_10) + digit;
  return true;
}

static const char *parse_decimal(const char *cursor, uint32_t max, uint32_t *value)
{
  if (!is_digit_character(*cursor))
  {
    return NULL;
  }

  if (cursor[0] == '0' && is_digit_character(cursor[1]))
  {
    return NULL;
  }

  uint32_t parsed_value = 0;

  while (is_digit_character(*cursor))
  {
    if (!append_digit_to_octet(*cursor, max, &parsed_value))
    {
      return NULL;
    }
    cursor++;
  }
  *value = parsed_value;
  return cursor;
}

/**
 * Scan the next whitespace-separated token from the range [cursor, end) into
 * the destination buffer (which must hold up to `buffer_size` bytes).
 *
 * Returns a pointer to the character immediately following the token,
 * or NULL if the token is missing, empty, or exceeds the buffer size.
 */
static const char *scan_next_token(const char *cursor, const char *end, char *buffer, size_t buffer_size)
{
  while (cursor < end && (*cursor == ' ' || *cursor == '\t'))
  {
    cursor++;
  }

  if (cursor >= end)
  {
    return NULL;
  }

  const char *token_start = cursor;
  while (cursor < end && *cursor != ' ' && *cursor != '\t')
  {
    cursor++;
  }

  size_t token_length = (size_t)(cursor - token_start);

  if (token_length == 0 || token_length >= buffer_size)
  {
    return NULL;
  }

  memcpy(buffer, token_start, token_length);
  buffer[token_length] = '\0';

  return cursor;
}
/* ------------------------------------------------------------------------
 * Task 1 - Address parsing and formatting
 * --------------------------------------------------------------------- */

bool ip_parse(const char *text, uint32_t *addr)
{
  if (text == NULL || addr == NULL)
  {
    return false;
  }

  uint32_t result = 0;

  for (int i = 0; i < 4; i++)
  {
    if (i > 0)
    {
      if (*text != '.')
      {
        return false;
      }
      text++;
    }

    unsigned int octet;
    text = parse_decimal(text, MAXIMUM_DECIMAL_VALUE_PER_OCTET, &octet);
    if (text == NULL)
    {
      return false;
    }

    result = (result << 8) | octet;
  }

  if (*text != '\0')
  {
    return false;
  }

  *addr = result;
  return true;
}

void ip_format(uint32_t addr, char out[IP_STR_LEN])
{
  snprintf(out, IP_STR_LEN, "%u.%u.%u.%u",
           (unsigned int)((addr >> 24) & MAXIMUM_DECIMAL_VALUE_PER_OCTET),
           (unsigned int)((addr >> 16) & MAXIMUM_DECIMAL_VALUE_PER_OCTET),
           (unsigned int)((addr >> 8) & MAXIMUM_DECIMAL_VALUE_PER_OCTET),
           (unsigned int)(addr & MAXIMUM_DECIMAL_VALUE_PER_OCTET));
}

bool cidr_parse(const char *text, cidr_t *block)
{
  if (text == NULL || block == NULL)
  {
    return false;
  }
  const char *slash = strchr(text, '/');
  if (slash == NULL || strchr(slash + 1, '/') != NULL)
  {
    return false;
  }
  // Extract and validate the IP address portion before the slash
  size_t address_len = (size_t)(slash - text);
  if (address_len == 0 || address_len >= IP_STR_LEN)
  {
    return false;
  }

  char address[IP_STR_LEN];
  memcpy(address, text, address_len);
  address[address_len] = '\0';

  cidr_t parsed;
  if (!ip_parse(address, &parsed.addr))
  {
    return false;
  }

  const char *prefix_text = slash + 1;
  uint32_t prefix;

  const char *end = parse_decimal(prefix_text, MAXIMUM_DECIMAL_PREFIX_VALUE, &prefix);
  if (end == NULL || *end != '\0' || prefix > MAXIMUM_DECIMAL_PREFIX_VALUE)
  {
    return false; // Invalid prefix value, parsing error, or trailing characters
  }

  parsed.prefix = (uint8_t)prefix;
  *block = parsed;
  return true;
}

void cidr_format(cidr_t block, char out[CIDR_STR_LEN])
{
  char address[IP_STR_LEN];
  ip_format(block.addr, address);
  (void)snprintf(out, CIDR_STR_LEN, "%s/%u", address,
                 bound_prefix(block.prefix));
}

/* ------------------------------------------------------------------------
 * Task 2 - Subnet arithmetic
 * --------------------------------------------------------------------- */

uint32_t cidr_mask(uint8_t prefix)
{
  prefix = bound_prefix(prefix);
  if (prefix == 0)
  {
    return 0;
  }
  return UINT32_MAX << (MAXIMUM_DECIMAL_PREFIX_VALUE - prefix);
}

uint32_t cidr_network(cidr_t block)
{
  return block.addr & cidr_mask(block.prefix);
}

uint32_t cidr_broadcast(cidr_t block)
{
  return block.addr | ~cidr_mask(block.prefix);
}

uint32_t cidr_first_host(cidr_t block)
{
  uint32_t network = cidr_network(block);
  return bound_prefix(block.prefix) >= 31 ? network : network + 1;
}

uint32_t cidr_last_host(cidr_t block)
{
  uint32_t broadcast = cidr_broadcast(block);
  return bound_prefix(block.prefix) >= 31 ? broadcast : broadcast - 1;
}

uint64_t cidr_host_count(cidr_t block)
{
  uint8_t prefix = bound_prefix(block.prefix);
  if (prefix == 32)
  {
    return 1;
  }
  if (prefix == 31)
  {
    return 2;
  }
  return (UINT64_C(1) << (32 - prefix)) - 2;
}

bool cidr_contains(cidr_t block, uint32_t addr)
{
  uint32_t mask = cidr_mask(block.prefix);
  return (addr & mask) == (block.addr & mask);
}

bool cidr_is_network(cidr_t block)
{
  return cidr_network(block) == block.addr;
}

bool cidr_subnet(cidr_t block, uint32_t n, uint32_t i, cidr_t *out)
{
  if (out == NULL || n == 0 || !cidr_is_network(block) || block.prefix > 32)
  {
    return false;
  }
  // Ensure n is a power of two and the index i is within bounds (0 <= i < n)
  if ((n & (n - 1U)) != 0 || i >= n)
  {
    return false;
  }

  uint32_t bits = 0;
  while ((UINT32_C(1) << bits) < n)
  {
    bits++;
  }
  uint32_t prefix = bound_prefix(block.prefix) + bits;
  if (prefix > 32 || i >= n)
  {
    return false;
  }
  uint64_t subnet_size = UINT64_C(1) << (32U - prefix);
  *out = (cidr_t){
      .addr = (uint32_t)((uint64_t)block.addr + (uint64_t)i * subnet_size),
      .prefix = (unsigned char)prefix};

  return true;
}

/* ------------------------------------------------------------------------
 * Task 3 - Longest prefix match
 * --------------------------------------------------------------------- */

struct fwd_table
{
  route_t *routes;
  size_t count;
  size_t capacity;
};

bool route_parse(const char *line, route_t *route)
{

  if (line == NULL || route == NULL)
  {
    return false;
  }

  const char *start = line;
  while (is_space_character(*start))
  {
    start++;
  }

  const char *end = start + strlen(start);
  while (end > start && is_space_character(end[-1]))
  {
    end--;
  }

  char dest_str[CIDR_STR_LEN];
  char gateway_str[IP_STR_LEN];
  char dev_str[DEV_NAME_LEN];

  const char *p = scan_next_token(start, end, dest_str, sizeof(dest_str));
  if (p != NULL)
  {
    p = scan_next_token(p, end, gateway_str, sizeof(gateway_str));
  }
  if (p != NULL)
  {
    p = scan_next_token(p, end, dev_str, sizeof(dev_str));
  }

  if (p == NULL || p != end)
  {
    return false;
  }

  route_t parsed;
  memset(&parsed, 0, sizeof(parsed));

  if (strcmp(dest_str, "default") == 0)
  {
    parsed.dest.addr = 0;
    parsed.dest.prefix = 0;
  }
  else
  {
    if (!cidr_parse(dest_str, &parsed.dest) || !cidr_is_network(parsed.dest))
    {
      return false;
    }
  }

  // 2. Parse Gateway (IPv4 address or "direct")
  if (strcmp(gateway_str, "direct") == 0)
  {
    parsed.gateway = 0;
  }
  else
  {
    if (!ip_parse(gateway_str, &parsed.gateway))
    {
      return false;
    }
  }

  for (const char *c = dev_str; *c != '\0'; c++)
  {
    if (is_space_character(*c))
    {
      return false;
    }
  }
  memcpy(parsed.dev, dev_str, strlen(dev_str) + 1);

  *route = parsed;
  return true;
}

fwd_table_t *table_create(void)
{
  return calloc(1, sizeof(fwd_table_t));
}

void table_destroy(fwd_table_t *table)
{
  if (table == NULL)
  {
    return;
  }
  free(table->routes);
  free(table);
}

size_t table_count(const fwd_table_t *table)
{
  return table == NULL ? 0 : table->count;
}

bool table_add(fwd_table_t *table, const route_t *route)
{
  if (table == NULL || route == NULL || !cidr_is_network(route->dest))
  {
    return false;
  }

  // Check for duplicate routes using normalized prefix comparison
  uint8_t normalized_prefix = bound_prefix(route->dest.prefix);
  for (size_t i = 0; i < table->count; ++i)
  {
    const cidr_t *existing_dest = &table->routes[i].dest;
    if (existing_dest->addr == route->dest.addr && bound_prefix(existing_dest->prefix) == normalized_prefix)
    {
      return false; // Route already exists
    }
  }

  if (table->count == table->capacity)
  {
    size_t new_capacity = table->capacity == 0 ? 8U : table->capacity * 2U;
    route_t *grown_routes = realloc(table->routes, new_capacity * sizeof(*grown_routes));

    if (grown_routes == NULL)
    {               // GCOVR_EXCL_START
      return false; // realloc failed, original table remains intact and valid
    } // GCOVR_EXCL_STOP

    table->routes = grown_routes;
    table->capacity = new_capacity;
  }

  route_t *slot = &table->routes[table->count++];
  *slot = *route;
  slot->dev[DEV_NAME_LEN - 1] = '\0';

  return true;
}

bool table_load(fwd_table_t *table, FILE *in, size_t *bad_line)
{
  if (bad_line != NULL)
  {
    *bad_line = 0;
  }
  if (table == NULL || in == NULL)
  {
    return false;
  }

  char *line_buffer = NULL;
  size_t buffer_capacity = 0;
  size_t current_line_number = 0;
  bool load_successful = true;

  while (getline(&line_buffer, &buffer_capacity, in) != -1)
  {
    current_line_number++;

    char *comment_marker = strchr(line_buffer, '#');
    if (comment_marker != NULL)
    {
      *comment_marker = '\0';
    }

    const char *cursor = line_buffer;
    while (is_space_character(*cursor))
    {
      cursor++;
    }
    if (*cursor == '\0')
    {
      continue;
    }

    route_t parsed_route;
    if (!route_parse(line_buffer, &parsed_route) || !table_add(table, &parsed_route))
    {
      if (bad_line != NULL)
      {
        *bad_line = current_line_number;
      }
      load_successful = false;
      break;
    }
  }

  // Check for stream reading errors (keeping bad_line as 0 if file I/O failed)
  if (load_successful && ferror(in))
  {
    load_successful = false;
  }

  free(line_buffer);
  return load_successful;
}

const route_t *table_lookup(const fwd_table_t *table, uint32_t dest)
{

  if (table == NULL)
  {
    return NULL;
  }

  const route_t *best_match = NULL;

  for (size_t i = 0; i < table->count; ++i)
  {
    const route_t *candidate_route = &table->routes[i];

    if (cidr_contains(candidate_route->dest, dest))
    {
      if (best_match == NULL ||
          bound_prefix(candidate_route->dest.prefix) > bound_prefix(best_match->dest.prefix))
      {
        best_match = candidate_route;
      }
    }
  }

  return best_match;
}
