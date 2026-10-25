#include "lab.h"
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#ifdef TEST
#define main main_exclude
#endif

static void usage(FILE *out)
{
    fprintf(out, "Usage: myapp info <address>/<prefix>\n"
                 "       myapp split <network>/<prefix> <count>\n"
                 "       myapp lookup <table-file> <address>...\n");
}

static int info(const char *arg)
{
    cidr_t block;
    char address[IP_STR_LEN];
    char mask[IP_STR_LEN];
    char network[IP_STR_LEN];
    char broadcast[IP_STR_LEN];
    char first[IP_STR_LEN];
    char last[IP_STR_LEN];

    if (!cidr_parse(arg, &block))
    {
        fprintf(stderr, "myapp: critical failure - '%s': not a valid CIDR block\n", arg);
        return EXIT_BAD_CMD_OR_MALFORMED;
    }

    ip_format(block.addr, address);
    ip_format(cidr_mask(block.prefix), mask);
    ip_format(cidr_network(block), network);
    ip_format(cidr_broadcast(block), broadcast);
    ip_format(cidr_first_host(block), first);
    ip_format(cidr_last_host(block), last);
    (void)printf("address    %s\n", address);
    (void)printf("prefix     /%u\n", bound_prefix(block.prefix));
    (void)printf("netmask    %s\n", mask);
    (void)printf("network    %s\n", network);
    (void)printf("broadcast  %s\n", broadcast);
    (void)printf("first host %s\n", first);
    (void)printf("last host  %s\n", last);
    (void)printf("hosts      %" PRIu64 "\n", cidr_host_count(block));

    return EXIT_SUCCESS;
}

static int lookup(int argc, char **argv)
{
    if (argc < 4)
    {
        fprintf(stderr, "myapp: 'lookup' expects at least 2 arguments (<table-file> <address>...), but got %d\n", argc - 2);
        usage(stderr);
        return EXIT_BAD_CMD_OR_MALFORMED;
    }

    const char *table_path = argv[2];
    FILE *in = fopen(table_path, "r");
    if (in == NULL)
    {
        (void)fprintf(stderr, "myapp: error opening table file '%s': %s\n", table_path, strerror(errno));
        return EXIT_UNOPENED_TABLE_OR_BAD_LINE;
    }

    fwd_table_t *table = table_create();
    if (table == NULL)
    {
        (void)fprintf(stderr, "myapp: critical failure — failed to allocate memory for route table\n");
        fclose(in);
        return EXIT_UNOPENED_TABLE_OR_BAD_LINE;
    }

    size_t bad_line;
    bool loaded = table_load(table, in, &bad_line);
    fclose(in);

    if (!loaded)
    {
        if (bad_line > 0)
        {
            fprintf(stderr, "myapp: critical failure — %s:%zu: route appears to be invalid\n", table_path, bad_line);
        }
        else
        {
            fprintf(stderr, "myapp: critical failure — %s: could not be read\n", table_path);
        }
        table_destroy(table);
        return EXIT_UNOPENED_TABLE_OR_BAD_LINE;
    }

    bool saw_bad_address = false;
    bool saw_unmatched = false;

    // Process all destination addresses provided as command-line arguments
    for (int i = 3; i < argc; ++i)
    {
        uint32_t dest;
        if (!ip_parse(argv[i], &dest))
        {
            fprintf(stderr, "myapp: critical failure — %s: not a valid address\n", argv[i]);
            saw_bad_address = true;
            continue;
        }

        char formatted_addr[IP_STR_LEN];
        ip_format(dest, formatted_addr);

        const route_t *route = table_lookup(table, dest);
        if (route == NULL)
        {
            printf("not able to reach the following address: %s\n", formatted_addr);
            saw_unmatched = true;
        }
        else if (route->gateway == 0)
        {
            printf("%s dev %s\n", formatted_addr, route->dev);
        }
        else
        {
            char gateway_addr[IP_STR_LEN];
            ip_format(route->gateway, gateway_addr);
            printf("%s via %s dev %s\n", formatted_addr, gateway_addr, route->dev);
        }
    }

    table_destroy(table);

    if (saw_bad_address)
    {
        return EXIT_BAD_CMD_OR_MALFORMED;
    }
    return saw_unmatched ? EXIT_NO_ROUTE_MATCH : EXIT_SUCCESS;
}
static int split(const char *block_arg, const char *count_arg)
{
    cidr_t block;
    cidr_t subnet;
    uint32_t count;

    if (!cidr_parse(block_arg, &block))
    {
        fprintf(stderr, "myapp: critical failure - failed to parse '%s' as a valid network identifier\n", block_arg);
        return EXIT_BAD_CMD_OR_MALFORMED;
    }

    if (!cidr_is_network(block))
    {
        char normalized_network[CIDR_STR_LEN];
        cidr_format((cidr_t){cidr_network(block), block.prefix}, normalized_network);
        fprintf(stderr, "myapp: critical failure - network address '%s' contains non-zero host bits (did you mean %s?)\n",
                block_arg, normalized_network);
        return EXIT_BAD_CMD_OR_MALFORMED;
    }

    if (count_arg[0] < '1' || count_arg[0] > '9')
    {
        fprintf(stderr, "myapp: critical failure - split count '%s' must be a power of two from 1 up (e.g., 2, 4, 8, 16)\n", count_arg);
        return EXIT_BAD_CMD_OR_MALFORMED;
    }

    uint64_t v = 0;
    for (const char *p = count_arg; *p != '\0'; p++)
    {
        if (*p < '0' || *p > '9')
        {
            fprintf(stderr, "myapp: critical failure - split count '%s' must be a power of two from 1 up (e.g., 2, 4, 8, 16)\n", count_arg);
            return EXIT_BAD_CMD_OR_MALFORMED;
        }
        v = v * 10 + (uint64_t)(*p - '0');
        if (v > UINT32_MAX)
        {
            fprintf(stderr, "myapp: critical failure - split count '%s' must be a power of two from 1 up (e.g., 2, 4, 8, 16)\n", count_arg);
            return EXIT_BAD_CMD_OR_MALFORMED;
        }
    }

    count = (uint32_t)v;

    if ((count & (count - 1U)) != 0)
    {
        fprintf(stderr, "myapp: critical failure - split count '%s' must be a power of two from 1 up (e.g., 2, 4, 8, 16)\n", count_arg);
        return EXIT_BAD_CMD_OR_MALFORMED;
    }

    for (uint32_t i = 0; i < count; ++i)
    {
        char formatted_subnet[CIDR_STR_LEN];

        if (!cidr_subnet(block, count, i, &subnet))
        {
            fprintf(stderr, "myapp: critical failure - prefix limit exceeded when attempting to split %s into %u parts\n",
                    block_arg, count);
            return EXIT_BAD_CMD_OR_MALFORMED;
        }

        cidr_format(subnet, formatted_subnet);
        printf("%s\n", formatted_subnet);
    }

    return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{

    if (argc == 1)
    {
        usage(stdout);
        return EXIT_SUCCESS;
    }

    const char *command = argv[1];

    if (strcmp(command, "info") == 0)
    {
        if (argc != 3)
        {
            fprintf(stderr, "myapp: 'info' expects 1 argument (<address>/<prefix>), but got %d\n", argc - 2);
            usage(stderr);
            return EXIT_BAD_CMD_OR_MALFORMED;
        }
        return info(argv[2]);
    }

    if (strcmp(command, "split") == 0)
    {
        if (argc != 4)
        {
            fprintf(stderr, "myapp: 'split' expects 2 arguments (<network>/<prefix> <count>), but got %d\n", argc - 2);
            usage(stderr);
            return EXIT_BAD_CMD_OR_MALFORMED;
        }
        return split(argv[2], argv[3]);
    }

    if (strcmp(command, "lookup") == 0)
    {
        if (argc < 4)
        {
            fprintf(stderr, "myapp: 'lookup' expects at least 2 arguments (<table-file> <address>...), but got %d\n", argc - 2);
            usage(stderr);
            return EXIT_BAD_CMD_OR_MALFORMED;
        }
        return lookup(argc, argv);
    }

    fprintf(stderr, "myapp: unknown command '%s'\n", command);
    usage(stderr);
    return EXIT_BAD_CMD_OR_MALFORMED;
}