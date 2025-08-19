#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <vector>

static void msg(const char *msg)
{
    fprintf(stderr, "%s\n", msg);
}

static void die(const char *msg)
{
    int err = errno;
    fprintf(stderr, "[%d] %s\n", err, msg);
    abort();
}

static int32_t read_full(int fd, uint8_t *buf, size_t n)
{
    while (n > 0)
    {
        ssize_t rv = read(fd, buf, n);
        if (rv <= 0)
        {
            return -1; // error, or unexpected EOF
        }
        assert((size_t)rv <= n);
        n -= (size_t)rv;
        buf += rv;
    }
    return 0;
}

static int32_t write_all(int fd, const uint8_t *buf, size_t n)
{
    while (n > 0)
    {
        ssize_t rv = write(fd, buf, n);
        if (rv <= 0)
        {
            return -1; // error
        }
        assert((size_t)rv <= n);
        n -= (size_t)rv;
        buf += rv;
    }
    return 0;
}

// append to the back
static void
buf_append(std::vector<uint8_t> &buf, const uint8_t *data, size_t len)
{
    buf.insert(buf.end(), data, data + len);
}

const size_t k_max_msg = 32 << 20; // likely larger than the kernel buffer

static int32_t send_req(int fd, const uint8_t *text, size_t len)
{
    if (len > k_max_msg)
    {
        return -1;
    }

    std::vector<uint8_t> wbuf;
    uint32_t msg_len = (uint32_t)len;
    buf_append(wbuf, (const uint8_t *)&msg_len, 4);
    buf_append(wbuf, text, len);
    return write_all(fd, wbuf.data(), wbuf.size());
}

static int32_t read_res(int fd)
{
    // 4 bytes header
    std::vector<uint8_t> rbuf;
    rbuf.resize(4);
    errno = 0;
    int32_t err = read_full(fd, &rbuf[0], 4);
    if (err)
    {
        if (errno == 0)
        {
            msg("EOF");
        }
        else
        {
            msg("read() error");
        }
        return err;
    }

    uint32_t len = 0;
    memcpy(&len, rbuf.data(), 4); // assume little endian
    if (len > k_max_msg)
    {
        msg("too long");
        return -1;
    }

    // reply body
    rbuf.resize(4 + len);
    err = read_full(fd, &rbuf[4], len);
    if (err)
    {
        msg("read() error");
        return err;
    }

    // print the response
    printf("server response: len:%u data:%.*s\n", len, (int)len, &rbuf[4]);
    return 0;
}

// Helper function to send a command string
static int32_t send_command(int fd, const char *cmd)
{
    size_t len = strlen(cmd);
    return send_req(fd, (const uint8_t *)cmd, len);
}

int main()
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        die("socket()");
    }

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = ntohs(1234);
    addr.sin_addr.s_addr = ntohl(INADDR_LOOPBACK); // 127.0.0.1
    int rv = connect(fd, (const struct sockaddr *)&addr, sizeof(addr));
    if (rv)
    {
        die("connect");
    }

    printf("Connected to key-value server at 127.0.0.1:1234\n");
    printf("Sending test commands...\n\n");

    // Define test commands as C strings
    const char *commands[] = {
        "SET mykey hello_world",
        "GET mykey",
        "SET number 12345",
        "GET number",
        "SET test_key some_test_value",
        "GET test_key",
        "DEL mykey",
        "GET mykey",       // should return NIL
        "DEL nonexistent", // should return NIL
        "GET nonexistent"  // should return NIL
    };

    size_t num_commands = sizeof(commands) / sizeof(commands[0]);

    // Declare variables that could be used after goto
    const char *invalid_commands[] = {
        "INVALID_CMD key",
        "SET", // missing key and value
        "GET", // missing key
        ""     // empty command
    };
    size_t num_invalid = sizeof(invalid_commands) / sizeof(invalid_commands[0]);

    // Send all commands (pipelined)
    printf("Sending %zu commands:\n", num_commands);
    for (size_t i = 0; i < num_commands; ++i)
    {
        printf("  [%zu] %s\n", i + 1, commands[i]);
        int32_t err = send_command(fd, commands[i]);
        if (err)
        {
            printf("Failed to send command: %s\n", commands[i]);
            goto L_DONE;
        }
    }

    printf("\nReceiving responses:\n");
    // Read all responses
    for (size_t i = 0; i < num_commands; ++i)
    {
        printf("  [%zu] ", i + 1);
        int32_t err = read_res(fd);
        if (err)
        {
            printf("Failed to read response for command %zu\n", i + 1);
            goto L_DONE;
        }
    }

    printf("\nTesting large value...\n");
    // Test with a large value
    char large_cmd[1024];
    char large_value[500];
    memset(large_value, 'A', sizeof(large_value) - 1);
    large_value[sizeof(large_value) - 1] = '\0';

    snprintf(large_cmd, sizeof(large_cmd), "SET large_key %s", large_value);

    if (send_command(fd, large_cmd) == 0)
    {
        printf("Sent large SET command\n");
        printf("Response: ");
        read_res(fd);

        if (send_command(fd, "GET large_key") == 0)
        {
            printf("Sent GET large_key\n");
            printf("Response: ");
            read_res(fd);
        }
    }

    printf("\nTesting invalid commands...\n");

    for (size_t i = 0; i < num_invalid; ++i)
    {
        printf("Sending invalid command: '%s'\n", invalid_commands[i]);
        if (send_command(fd, invalid_commands[i]) == 0)
        {
            printf("Response: ");
            read_res(fd);
        }
    }

L_DONE:
    printf("\nClosing connection...\n");
    close(fd);
    return 0;
}