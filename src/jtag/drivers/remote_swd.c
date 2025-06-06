// SPDX-License-Identifier: GPL-2.0-or-later

/***************************************************************************
 *   Copyright (C) 2025 by Brian Kuschak <bkuschak@gmail.com>              *
 *   Adapted from remote_bitbang.c                                         *
 *                                                                         *
 *   Controls a remote SWD programmer over TCP/IP. Much faster than using  *
 *   the remote_bitbang driver. Lightweight remote-side implementation.    *
 *   Supports SWD only. JTAG not supported.                                *
 *                                                                         *
 *   Tested using a XIAO ESP32C6 as the programmer and STM32 Blue Pill as  *
 *   the target. Flash programming performance: 9.5 KB/sec.                *
 *                                                                         *
 *       openocd \                                                         *
 *           --search tcl \                                                *
 *           -c "debug_level 2" \                                          *
 *           -c "reset_config none" \                                      *
 *           -c "adapter driver remote_swd" \                              *
 *           -c "remote_swd host 192.168.100.40" \                         *
 *           -c "remote_swd port 5253" \                                   *
 *           -f tcl/target/stm32f1x.cfg \                                  *
 *           -c "program firmware.elf verify reset exit"                   *
 *                                                                         *
 *   Refer to the implementation of the remote-side firmware for ESP32 at  *
 *   https://github.com/bkuschak/openocd_remote_swd_esp32                  *
 *                                                                         *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef _WIN32
#include <sys/un.h>
#include <netdb.h>
#include <netinet/tcp.h>
#endif
#include <arpa/inet.h>
#include "bitbang.h"
#include "helper/system.h"
#include "helper/replacements.h"
#include <jtag/interface.h>

// Define our version of the protocol used.  Remote side must match.
#define PROTOCOL_VERSION        0x01

// Arbitrary limit on host name length.
#define REMOTE_SWD_HOST_MAX     255

// First 4 bits of the flags hold the operation code.
#define FLAGS_OP_PROTOCOL       (1<<0)      // Get remote protocol version.
#define FLAGS_OP_VERSION        (2<<0)      // Get remote HW/SW version.
#define FLAGS_OP_SERIAL_NUM     (3<<0)      // Get remote serial number.
#define FLAGS_OP_SPEED          (4<<0)      // Set speed in 'data' field.
#define FLAGS_OP_RESET          (5<<0)      // Set NRST state in 'data' field.
#define FLAGS_OP_SWITCH_SEQ     (6<<0)      // Send sequence in 'data' field.
#define FLAGS_OP_READ_REG       (7<<0)      // SWD read register.
#define FLAGS_OP_WRITE_REG      (8<<0)      // SWD write register.
#define FLAGS_OP(flags)         (flags & 0x0F)

// Remaining bits are reserved for flags.
#define FLAGS_EXPECT_ACK        (1<<4)
#define FLAGS_EXPECT_DATA       (1<<5)
#define FLAGS_SRST_OPEN_DRAIN   (1<<4)      // Used for OP_RESET only.

// The 3 ACK bits returned by the target.
#define ACK_OK                  (1<<0)
#define ACK_WAIT                (1<<1)
#define ACK_FAULT               (1<<2)

// The maximum number of queued commands, before we write them to the target.
#define MAX_QUEUE_LEN           128

// Very simple TCP stream protocol.
// We send commands to the remote side, using the struct below.
// The remote side returns the same struct back to us, with the ack field set,
// and the data field set if the command was a read. The cmd, ack, and data
// fields are what is actually transmitted on the wire, SWDIO.
struct queued_command {
    uint8_t flags;          // Opcode and flags.
    uint8_t ap_delay_clks;  // Additional clock cycles sent after the data.
    uint8_t cmd;            // SWD command.
    uint8_t ack;            // SWD ACK (3 bits) returned.
    uint32_t data;          // SWD data, sent or returned.
};

enum flush_bool {
    NO_FLUSH,
    FLUSH_SEND_BUF
};

static char *remote_swd_host;
static char *remote_swd_port;
static int sockfd;

// The queued commands and a write index.
static struct queued_command queued_commands[MAX_QUEUE_LEN];
static unsigned int queued_commands_idx;

// We need a place to store the return data pointers. These are the caller's
// pointers for storing response data, and the ACK responses.
static uint32_t* response_data[MAX_QUEUE_LEN];
static uint8_t response_acks[MAX_QUEUE_LEN];

static int remote_swd_run_queue(void);

static int remote_swd_queue(struct queued_command* cmd, uint32_t* response,
        enum flush_bool flush)
{
    // Use network byte order in the packets.
    queued_commands[queued_commands_idx] = *cmd;
    queued_commands[queued_commands_idx].data = htonl(cmd->data);

    response_data[queued_commands_idx] = response;

    if(response == NULL)
        LOG_DEBUG_IO("No response pointer provided.");
    queued_commands_idx++;
    if (flush == FLUSH_SEND_BUF || queued_commands_idx >=
            ARRAY_SIZE(queued_commands))
        return remote_swd_run_queue();
    return ERROR_OK;
}

static int remote_swd_quit(void)
{
    LOG_DEBUG("remote_swd interface quit");

    if (close_socket(sockfd) != 0) {
        log_socket_error("close_socket");
        return ERROR_FAIL;
    }

    free(remote_swd_host);
    free(remote_swd_port);
    return ERROR_OK;
}

static int remote_swd_reset(int trst, int srst)
{
    /* SRST only. SWD doesn't have TRST. */
    bool srst_open_drain = true;
    enum reset_types cfg = jtag_get_reset_config();
    if (cfg & RESET_SRST_PUSH_PULL)
        srst_open_drain = false;

    LOG_INFO("RESET: srst=%d, open_drain=%d", srst, srst_open_drain);

    struct queued_command cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.flags = FLAGS_OP_RESET;
    cmd.flags |= srst_open_drain ? FLAGS_SRST_OPEN_DRAIN : 0;
    cmd.data = srst ? 1 : 0;

    /* Always flush the send buffer on reset */
    return remote_swd_queue(&cmd, NULL, NO_FLUSH);
}

static int remote_swd_speed(int hz)
{
    LOG_DEBUG("SPEED: %d Hz", hz);

    struct queued_command command;
    memset(&command, 0, sizeof(command));
    command.flags = FLAGS_OP_SPEED;
    command.data = hz;
    return remote_swd_queue(&command, NULL, NO_FLUSH);
}

static void remote_swd_write_reg(unsigned char cmd, unsigned int value,
        unsigned int ap_delay_clk)
{
    LOG_DEBUG("WRITE_REG: cmd=0x%02x, value=0x%08x, ap_delay_clk=%d",
            cmd, value, ap_delay_clk);

    struct queued_command command;
    memset(&command, 0, sizeof(command));
    command.flags = FLAGS_OP_WRITE_REG;
    command.flags |= FLAGS_EXPECT_ACK;
    command.cmd = cmd | SWD_CMD_START | SWD_CMD_PARK;
    command.data = value;
    command.ap_delay_clks = ap_delay_clk;

    if (remote_swd_queue(&command, NULL, NO_FLUSH) == ERROR_FAIL) {
        LOG_ERROR("write_reg failed");
    }
}

static void remote_swd_read_reg(unsigned char cmd, unsigned int *value,
        unsigned int ap_delay_clk)
{
    LOG_DEBUG("READ_REG: cmd=0x%02x, ap_delay_clk=%d", cmd,
            ap_delay_clk);

    struct queued_command command;
    memset(&command, 0, sizeof(command));
    command.flags = FLAGS_OP_READ_REG;
    command.flags |= FLAGS_EXPECT_ACK;
    command.flags |= FLAGS_EXPECT_DATA;
    command.cmd = cmd | SWD_CMD_START | SWD_CMD_PARK;
    command.ap_delay_clks = ap_delay_clk;

    if (remote_swd_queue(&command, value, NO_FLUSH) == ERROR_FAIL) {
        LOG_ERROR("read_reg failed");
    }
}

static int remote_swd_switch_seq(enum swd_special_seq seq)
{
    LOG_DEBUG("SWITCH_SEQ: %d", seq);

    struct queued_command command;
    memset(&command, 0, sizeof(command));
    command.flags = FLAGS_OP_SWITCH_SEQ;
    command.data = seq;

    if (remote_swd_queue(&command, NULL, NO_FLUSH) == ERROR_FAIL)
        return ERROR_FAIL;
    return 0;
}

static int remote_swd_protocol(unsigned int* value)
{
    LOG_DEBUG("PROTOCOL");

    struct queued_command command;
    memset(&command, 0, sizeof(command));
    command.flags = FLAGS_OP_PROTOCOL;
    command.flags |= FLAGS_EXPECT_DATA;

    if (remote_swd_queue(&command, value, FLUSH_SEND_BUF) == ERROR_FAIL)
        return ERROR_FAIL;
    return 0;
}

static int remote_swd_version(unsigned int* value)
{
    LOG_DEBUG("VERSION");

    struct queued_command command;
    memset(&command, 0, sizeof(command));
    command.flags = FLAGS_OP_VERSION;
    command.flags |= FLAGS_EXPECT_DATA;

    if (remote_swd_queue(&command, value, FLUSH_SEND_BUF) == ERROR_FAIL)
        return ERROR_FAIL;
    return 0;
}

static int remote_swd_serial_number(unsigned int* value)
{
    LOG_DEBUG("SERIAL_NUM");

    struct queued_command command;
    memset(&command, 0, sizeof(command));
    command.flags = FLAGS_OP_SERIAL_NUM;
    command.flags |= FLAGS_EXPECT_DATA;

    if (remote_swd_queue(&command, value, FLUSH_SEND_BUF) == ERROR_FAIL)
        return ERROR_FAIL;
    return 0;
}

static int remote_swd_init_tcp(void)
{
    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM
    };
    struct addrinfo *result, *rp;
    int fd = 0;

    LOG_INFO("Connecting to %s:%s",
            remote_swd_host ? remote_swd_host : "localhost",
            remote_swd_port);

    /* Obtain address(es) matching host/port */
    int s = getaddrinfo(remote_swd_host, remote_swd_port, &hints, &result);
    if (s != 0) {
        LOG_ERROR("getaddrinfo: %s\n", gai_strerror(s));
        return ERROR_FAIL;
    }

    /* getaddrinfo() returns a list of address structures.
     Try each address until we successfully connect(2).
     If socket(2) (or connect(2)) fails, we (close the socket
     and) try the next address. */

    for (rp = result; rp ; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd == -1)
            continue;

        if (connect(fd, rp->ai_addr, rp->ai_addrlen) != -1)
            break; /* Success */

        close(fd);
    }

    /* Set NODELAY to minimize latency. */
    int one = 1;
    /* On Windows optval has to be a const char *. */
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char *)&one, sizeof(one));

    freeaddrinfo(result); /* No longer needed */

    if (!rp) { /* No address succeeded */
        log_socket_error("Failed to connect");
        return ERROR_FAIL;
    }

    return fd;
}

static int remote_swd_swd_init(void)
{
    LOG_DEBUG("remote_swd_swd_init");
    return ERROR_OK;
}

static int remote_swd_init(void)
{
    LOG_INFO("Initializing remote_swd driver");

    memset(queued_commands, 0, sizeof(queued_commands));
    memset(response_data, 0, sizeof(response_data));
    memset(response_acks, 0, sizeof(response_acks));
    queued_commands_idx = 0;

    int ret = remote_swd_init_tcp();
    if (ret < 0) {
        log_socket_error("remote_swd socket init");
        LOG_ERROR("Failed initializing socket. Error: %d", errno);
        return ret;
    }
    sockfd = ret;

    LOG_INFO("remote_swd driver initialized");

    // Get device version and serial number.
    unsigned int protocol = 0;
    unsigned int version = 0;
    unsigned int serial_num = 0;
    ret = remote_swd_protocol(&protocol);
    if(ret != ERROR_OK) {
        LOG_ERROR("Failed getting remote protocol version!");
        return ERROR_FAIL;
    }
    ret = remote_swd_version(&version);
    if(ret != ERROR_OK) {
        LOG_ERROR("Failed getting remote version!");
        return ERROR_FAIL;
    }
    ret = remote_swd_serial_number(&serial_num);
    if(ret != ERROR_OK) {
        LOG_ERROR("Failed getting remote serial number!");
        return ERROR_FAIL;
    }

    LOG_INFO("Remote protocol version: %u", protocol);
    LOG_INFO("Remote HW/SW version: 0x%02hX / 0x%02hX",
            version & 0xFF, (version >> 8) & 0xFF);
    LOG_INFO("Remote serial number: %08X", serial_num);

    if(protocol != PROTOCOL_VERSION) {
        LOG_ERROR("Remote protocol version (%u) does not match our own (%u)!",
                protocol, PROTOCOL_VERSION);
        return ERROR_FAIL;
    }
    return ERROR_OK;
}

COMMAND_HANDLER(remote_swd_handle_remote_swd_port_command)
{
    if (CMD_ARGC == 1) {
        uint16_t port;
        COMMAND_PARSE_NUMBER(u16, CMD_ARGV[0], port);
        free(remote_swd_port);
        remote_swd_port = port == 0 ? NULL : strdup(CMD_ARGV[0]);
        LOG_INFO("remote_swd got port %s", remote_swd_port);
        return ERROR_OK;
    }
    return ERROR_COMMAND_SYNTAX_ERROR;
}

COMMAND_HANDLER(remote_swd_handle_remote_swd_host_command)
{
    if (CMD_ARGC == 1) {
        free(remote_swd_host);
        remote_swd_host = strdup(CMD_ARGV[0]);
        LOG_INFO("remote_swd got host %s", remote_swd_host);
        return ERROR_OK;
    }
    return ERROR_COMMAND_SYNTAX_ERROR;
}

static const struct command_registration remote_swd_subcommand_handlers[] = {
    {
        .name = "port",
        .handler = remote_swd_handle_remote_swd_port_command,
        .mode = COMMAND_CONFIG,
        .help = "Set the TCP port to use to connect to the remote SWD.\n",
        .usage = "port_number",
    },
    {
        .name = "host",
        .handler = remote_swd_handle_remote_swd_host_command,
        .mode = COMMAND_CONFIG,
        .help = "Set the host to use to connect to the remote SWD.\n",
        .usage = "host_name",
    },
    // TODO add subcommands to set the pin numbers for SWDIO, SWCLK, SRST.
    COMMAND_REGISTRATION_DONE
};

static const struct command_registration remote_swd_command_handlers[] = {
    {
        .name = "remote_swd",
        .mode = COMMAND_ANY,
        .help = "perform remote_swd management",
        .chain = remote_swd_subcommand_handlers,
        .usage = "",
    },
    COMMAND_REGISTRATION_DONE
};


static int remote_swd_run_queue(void)
{
    LOG_DEBUG("Executing %d queued transactions", queued_commands_idx);
    if (queued_commands_idx <= 0)
        return ERROR_OK;

    // Send entire queue at once.
    int nbytes = queued_commands_idx * sizeof(*queued_commands);
    LOG_DEBUG_IO("Sending %d bytes... (fd=%d)", nbytes, sockfd);
    ssize_t n = write_socket(sockfd, queued_commands, nbytes);
    LOG_DEBUG_IO("write_socket returned %zd", n);
    if (n < 0) {
        log_socket_error("remote_swd write_socket error");
        queued_commands_idx = 0;
        return ERROR_FAIL;
    }
    if (n != nbytes) {
        log_socket_error("remote_swd write_socket short write");
        queued_commands_idx = 0;
        return ERROR_FAIL;
    }

    // Wait for the entire response.
    struct queued_command response[queued_commands_idx];
    nbytes = sizeof(response);
    LOG_DEBUG_IO("Reading %d bytes...", nbytes);
    n = read_socket(sockfd, response, nbytes);
    LOG_DEBUG_IO("read_socket returned %zd", n);
    if (n < 0) {
        log_socket_error("remote_swd read_socket error");
        queued_commands_idx = 0;
        return ERROR_FAIL;
    }
    if (n != nbytes) {
        log_socket_error("remote_swd read_socket short read");
        queued_commands_idx = 0;
        return ERROR_FAIL;
    }

    // Iterate over the response data, storing the responses into the caller's
    // pointers.
    memset(response_acks, 0, sizeof(response_acks));
    for(unsigned i=0; i<queued_commands_idx; i++) {
        struct queued_command* cmd = &queued_commands[i];
        struct queued_command* resp = &response[i];

        if(response_data[i])
            *response_data[i] = 0;

        if(cmd->flags & FLAGS_EXPECT_ACK) {
            LOG_DEBUG("Got response ack: %x", resp->data);
            response_acks[i] = resp->ack;
        }
        if(cmd->flags & FLAGS_EXPECT_DATA) {
            LOG_DEBUG("Got response data: %08x", resp->data);
            if(response_data[i])
                *response_data[i] = ntohl(resp->data);
        }
    }

    LOG_DEBUG("SWD run_queue success");
    queued_commands_idx = 0;
    return ERROR_OK;
}

const struct swd_driver remote_swd_ops = {
    .init = remote_swd_swd_init,
    .switch_seq = remote_swd_switch_seq,
    .read_reg = remote_swd_read_reg,
    .write_reg = remote_swd_write_reg,
    .run = remote_swd_run_queue,
};

struct adapter_driver remote_swd_adapter_driver = {
    .name = "remote_swd",
    .transport_ids = TRANSPORT_SWD,
    .transport_preferred_id = TRANSPORT_SWD,
    .commands = remote_swd_command_handlers,
    .init = &remote_swd_init,
    .quit = &remote_swd_quit,
    .speed = &remote_swd_speed,
    .reset = &remote_swd_reset,
    .swd_ops = &remote_swd_ops,
};
