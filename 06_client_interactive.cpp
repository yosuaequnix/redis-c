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
static void buf_append(std::vector<uint8_t> &buf, const uint8_t *data, size_t len)
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
    printf("Server: %.*s\n", (int)len, &rbuf[4]);
    return 0;
}

// Helper function to send a command string
static int32_t send_command(int fd, const char *cmd)
{
    size_t len = strlen(cmd);
    return send_req(fd, (const uint8_t *)cmd, len);
}

// Remove trailing newline from input
static void trim_newline(char *str)
{
    size_t len = strlen(str);
    if (len > 0 && str[len - 1] == '\n')
    {
        str[len - 1] = '\0';
    }
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
    printf("Commands: GET <key>, SET <key> <value>, DEL <key>\n");
    printf("Type 'END' to quit\n");
    printf("----------------------------------------\n");

    char input[2048];
    while (true)
    {
        printf("> ");
        fflush(stdout);

        // Read user input
        if (fgets(input, sizeof(input), stdin) == NULL)
        {
            printf("\nEOF detected, closing connection...\n");
            break;
        }

        // Remove trailing newline
        trim_newline(input);

        // Check for END command
        if (strcmp(input, "END") == 0)
        {
            printf("Ending session...\n");
            break;
        }

        // Skip empty commands
        if (strlen(input) == 0)
        {
            continue;
        }

        // Send command to server
        if (send_command(fd, input) != 0)
        {
            printf("Failed to send command\n");
            break;
        }

        // Read and display response
        if (read_res(fd) != 0)
        {
            printf("Failed to read response\n");
            break;
        }
    }

    printf("Closing connection...\n");
    close(fd);
    return 0;
}