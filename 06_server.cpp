// stdlib
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
// system
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
// C++
#include <vector>
// hiredis
#include <hiredis/hiredis.h>

static void msg(const char *msg)
{
    fprintf(stderr, "%s\n", msg);
}

static void msg_errno(const char *msg)
{
    fprintf(stderr, "[errno:%d] %s\n", errno, msg);
}

static void die(const char *msg)
{
    fprintf(stderr, "[%d] %s\n", errno, msg);
    abort();
}

static void fd_set_nb(int fd)
{
    errno = 0;
    int flags = fcntl(fd, F_GETFL, 0);
    if (errno)
    {
        die("fcntl error");
        return;
    }

    flags |= O_NONBLOCK;

    errno = 0;
    (void)fcntl(fd, F_SETFL, flags);
    if (errno)
    {
        die("fcntl error");
    }
}

const size_t k_max_msg = 32 << 20; // likely larger than the kernel buffer
// Redis connection (global for simplicity)
static redisContext *redis_ctx = NULL;

// initialize Redis connection
static bool init_redis()
{
    redis_ctx = redisConnect("127.0.0.1", 6379);
    if (redis_ctx == NULL || redis_ctx->err)
    {
        if (redis_ctx)
        {
            fprintf(stderr, "Redis connection error: %s\n", redis_ctx->errstr);
            redisFree(redis_ctx);
        }
        else
        {
            fprintf(stderr, "Redis connection error: can't allocate redis context\n");
        }
        return false;
    }

    // Test the connection
    redisReply *reply = (redisReply *)redisCommand(redis_ctx, "PING");
    if (reply == NULL)
    {
        fprintf(stderr, "Redis PING failed\n");
        return false;
    }

    if (reply->type == REDIS_REPLY_STATUS && strcmp(reply->str, "PONG") == 0)
    {
        printf("Redis connection established\n");
    }
    else
    {
        printf("Unexpected Redis PING response\n");
    }

    freeReplyObject(reply);
    return true;
}

// Protocol: <command> <key> [value]
// Commands: GET, SET, DEL
enum Command
{
    CMD_GET,
    CMD_SET,
    CMD_DEL,
    CMD_UNKNOWN
};

struct ParsedRequest
{
    Command cmd;
    char key[256];
    char value[1024];
};

// Find next space or end of string
static const char *find_space_or_end(const char *start, const char *end)
{
    while (start < end && *start != ' ')
    {
        start++;
    }
    return start;
}

// Skip spaces
static const char *skip_spaces(const char *start, const char *end)
{
    while (start < end && *start == ' ')
    {
        start++;
    }
    return start;
}

// Copy substring to buffer with null termination
static void copy_substring(char *dest, size_t dest_size, const char *src, size_t len)
{
    size_t copy_len = len < dest_size - 1 ? len : dest_size - 1;
    memcpy(dest, src, copy_len);
    dest[copy_len] = '\0';
}

// Parse a request string into command, key, and optional value
static bool parse_request(const uint8_t *data, uint32_t len, ParsedRequest *req)
{
    const char *start = (const char *)data;
    const char *end = start + len;
    const char *pos = start;

    // Clear the request structure
    memset(req, 0, sizeof(*req));

    // Parse command
    const char *cmd_end = find_space_or_end(pos, end);
    if (cmd_end == pos)
    {
        return false; // No command
    }

    size_t cmd_len = cmd_end - pos;
    if (cmd_len == 3 && memcmp(pos, "GET", 3) == 0)
    {
        req->cmd = CMD_GET;
    }
    else if (cmd_len == 3 && memcmp(pos, "SET", 3) == 0)
    {
        req->cmd = CMD_SET;
    }
    else if (cmd_len == 3 && memcmp(pos, "DEL", 3) == 0)
    {
        req->cmd = CMD_DEL;
    }
    else
    {
        req->cmd = CMD_UNKNOWN;
        return false;
    }

    // Skip to key
    pos = skip_spaces(cmd_end, end);
    if (pos >= end)
    {
        return false; // No key
    }

    // Parse key
    const char *key_end = find_space_or_end(pos, end);
    copy_substring(req->key, sizeof(req->key), pos, key_end - pos);

    // Parse value if present (for SET command)
    if (key_end < end)
    {
        pos = skip_spaces(key_end, end);
        if (pos < end)
        {
            copy_substring(req->value, sizeof(req->value), pos, end - pos);
        }
    }

    return true;
}

// Execute Redis command and format response
static const char *execute_redis_command(const ParsedRequest *req)
{
    static char response_buffer[2048];

    if (!redis_ctx)
    {
        strcpy(response_buffer, "ERROR: Redis not connected");
        return response_buffer;
    }

    redisReply *reply = NULL;

    switch (req->cmd)
    {
    case CMD_GET:
        reply = (redisReply *)redisCommand(redis_ctx, "GET %s", req->key);
        if (reply == NULL)
        {
            strcpy(response_buffer, "ERROR: Redis command failed");
        }
        else if (reply->type == REDIS_REPLY_STRING)
        {
            snprintf(response_buffer, sizeof(response_buffer), "OK %s", reply->str);
        }
        else if (reply->type == REDIS_REPLY_NIL)
        {
            strcpy(response_buffer, "NIL");
        }
        else
        {
            strcpy(response_buffer, "ERROR: Unexpected reply type");
        }
        break;

    case CMD_SET:
        reply = (redisReply *)redisCommand(redis_ctx, "SET %s %s", req->key, req->value);
        if (reply == NULL)
        {
            strcpy(response_buffer, "ERROR: Redis command failed");
        }
        else if (reply->type == REDIS_REPLY_STATUS &&
                 strcmp(reply->str, "OK") == 0)
        {
            strcpy(response_buffer, "OK");
        }
        else
        {
            strcpy(response_buffer, "ERROR: SET failed");
        }
        break;

    case CMD_DEL:
        reply = (redisReply *)redisCommand(redis_ctx, "DEL %s", req->key);
        if (reply == NULL)
        {
            strcpy(response_buffer, "ERROR: Redis command failed");
        }
        else if (reply->type == REDIS_REPLY_INTEGER)
        {
            strcpy(response_buffer, reply->integer > 0 ? "OK" : "NIL");
        }
        else
        {
            strcpy(response_buffer, "ERROR: Unexpected reply type");
        }
        break;

    default:
        strcpy(response_buffer, "ERROR: Unknown command");
        break;
    }

    if (reply)
    {
        freeReplyObject(reply);
    }

    return response_buffer;
}

struct Conn
{
    int fd = -1;
    // application's intention, for the event loop
    bool want_read = false;
    bool want_write = false;
    bool want_close = false;
    // buffered input and output
    std::vector<uint8_t> incoming; // data to be parsed by the application
    std::vector<uint8_t> outgoing; // responses generated by the application
};

// append to the back
static void
buf_append(std::vector<uint8_t> &buf, const uint8_t *data, size_t len)
{
    buf.insert(buf.end(), data, data + len);
}

// remove from the front
static void buf_consume(std::vector<uint8_t> &buf, size_t n)
{
    buf.erase(buf.begin(), buf.begin() + n);
}

// application callback when the listening socket is ready
static Conn *handle_accept(int fd)
{
    // accept
    struct sockaddr_in client_addr = {};
    socklen_t addrlen = sizeof(client_addr);
    int connfd = accept(fd, (struct sockaddr *)&client_addr, &addrlen);
    if (connfd < 0)
    {
        msg_errno("accept() error");
        return NULL;
    }
    uint32_t ip = client_addr.sin_addr.s_addr;
    fprintf(stderr, "new client from %u.%u.%u.%u:%u\n",
            ip & 255, (ip >> 8) & 255, (ip >> 16) & 255, ip >> 24,
            ntohs(client_addr.sin_port));

    // set the new connection fd to nonblocking mode
    fd_set_nb(connfd);

    // create a `struct Conn`
    Conn *conn = new Conn();
    conn->fd = connfd;
    conn->want_read = true;
    return conn;
}

// process 1 request if there is enough data
static bool try_one_request(Conn *conn)
{
    // try to parse the protocol: message header
    if (conn->incoming.size() < 4)
    {
        return false; // want read
    }
    uint32_t len = 0;
    memcpy(&len, conn->incoming.data(), 4);
    if (len > k_max_msg)
    {
        msg("too long");
        conn->want_close = true;
        return false; // want close
    }
    // message body
    if (4 + len > conn->incoming.size())
    {
        return false; // want read
    }
    const uint8_t *request = &conn->incoming[4];

    // got one request, do some application logic
    printf("client says: len:%d data:%.*s\n",
           len, len < 100 ? len : 100, request);

    // generate the response (echo)
    buf_append(conn->outgoing, (const uint8_t *)&len, 4);
    buf_append(conn->outgoing, request, len);

    // application logic done! remove the request message.
    buf_consume(conn->incoming, 4 + len);
    // Q: Why not just empty the buffer? See the explanation of "pipelining".
    return true; // success
}

// application callback when the socket is writable
static void handle_write(Conn *conn)
{
    assert(conn->outgoing.size() > 0);
    ssize_t rv = write(conn->fd, &conn->outgoing[0], conn->outgoing.size());
    if (rv < 0 && errno == EAGAIN)
    {
        return; // actually not ready
    }
    if (rv < 0)
    {
        msg_errno("write() error");
        conn->want_close = true; // error handling
        return;
    }

    // remove written data from `outgoing`
    buf_consume(conn->outgoing, (size_t)rv);

    // update the readiness intention
    if (conn->outgoing.size() == 0)
    { // all data written
        conn->want_read = true;
        conn->want_write = false;
    } // else: want write
}

// application callback when the socket is readable
static void handle_read(Conn *conn)
{
    // read some data
    uint8_t buf[64 * 1024];
    ssize_t rv = read(conn->fd, buf, sizeof(buf));
    if (rv < 0 && errno == EAGAIN)
    {
        return; // actually not ready
    }
    // handle IO error
    if (rv < 0)
    {
        msg_errno("read() error");
        conn->want_close = true;
        return; // want close
    }
    // handle EOF
    if (rv == 0)
    {
        if (conn->incoming.size() == 0)
        {
            msg("client closed");
        }
        else
        {
            msg("unexpected EOF");
        }
        conn->want_close = true;
        return; // want close
    }
    // got some new data
    buf_append(conn->incoming, buf, (size_t)rv);

    // parse requests and generate responses
    while (try_one_request(conn))
    {
    }
    // Q: Why calling this in a loop? See the explanation of "pipelining".

    // update the readiness intention
    if (conn->outgoing.size() > 0)
    { // has a response
        conn->want_read = false;
        conn->want_write = true;
        // The socket is likely ready to write in a request-response protocol,
        // try to write it without waiting for the next iteration.
        return handle_write(conn);
    } // else: want read
}

int main()
{
    // the listening socket
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        die("socket()");
    }
    int val = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

    // bind
    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = ntohs(1234);
    addr.sin_addr.s_addr = ntohl(0); // wildcard address 0.0.0.0
    int rv = bind(fd, (const sockaddr *)&addr, sizeof(addr));
    if (rv)
    {
        die("bind()");
    }

    // set the listen fd to nonblocking mode
    fd_set_nb(fd);

    // listen
    rv = listen(fd, SOMAXCONN);
    if (rv)
    {
        die("listen()");
    }

    // a map of all client connections, keyed by fd
    std::vector<Conn *> fd2conn;
    // the event loop
    std::vector<struct pollfd> poll_args;
    while (true)
    {
        // prepare the arguments of the poll()
        poll_args.clear();
        // put the listening sockets in the first position
        struct pollfd pfd = {fd, POLLIN, 0};
        poll_args.push_back(pfd);
        // the rest are connection sockets
        for (Conn *conn : fd2conn)
        {
            if (!conn)
            {
                continue;
            }
            // always poll() for error
            struct pollfd pfd = {conn->fd, POLLERR, 0};
            // poll() flags from the application's intent
            if (conn->want_read)
            {
                pfd.events |= POLLIN;
            }
            if (conn->want_write)
            {
                pfd.events |= POLLOUT;
            }
            poll_args.push_back(pfd);
        }

        // wait for readiness
        int rv = poll(poll_args.data(), (nfds_t)poll_args.size(), -1);
        if (rv < 0 && errno == EINTR)
        {
            continue; // not an error
        }
        if (rv < 0)
        {
            die("poll");
        }

        // handle the listening socket
        if (poll_args[0].revents)
        {
            if (Conn *conn = handle_accept(fd))
            {
                // put it into the map
                if (fd2conn.size() <= (size_t)conn->fd)
                {
                    fd2conn.resize(conn->fd + 1);
                }
                assert(!fd2conn[conn->fd]);
                fd2conn[conn->fd] = conn;
            }
        }

        // handle connection sockets
        for (size_t i = 1; i < poll_args.size(); ++i)
        { // note: skip the 1st
            uint32_t ready = poll_args[i].revents;
            if (ready == 0)
            {
                continue;
            }

            Conn *conn = fd2conn[poll_args[i].fd];
            if (ready & POLLIN)
            {
                assert(conn->want_read);
                handle_read(conn); // application logic
            }
            if (ready & POLLOUT)
            {
                assert(conn->want_write);
                handle_write(conn); // application logic
            }

            // close the socket from socket error or application logic
            if ((ready & POLLERR) || conn->want_close)
            {
                (void)close(conn->fd);
                fd2conn[conn->fd] = NULL;
                delete conn;
            }
        } // for each connection sockets
    } // the event loop
    return 0;
}
