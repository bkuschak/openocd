// SPDX-License-Identifier: GPL-2.0-or-later

/***************************************************************************
 *   Copyright (C) 2025 by Brian Kuschak <bkuschak@gmail.com>              *
 *   Adapted from remote_bitbang.c                                         *
 *                                                                         *
 *   Controls a remote SWD programmer over TCP/IP. Much faster than using  *
 *   the remote_bitbang driver. Lightweight remote-side implementation.    *
 *   Tested with a cheap remote programmer built from the ESP32-C6-MINI    *
 *   dev board. Supports SWD only. JTAG not supported.                     *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef _WIN32
#include <sys/un.h>
#include <netdb.h>
#include <netinet/tcp.h>
#endif
#include "helper/system.h"
#include "helper/replacements.h"
#include <jtag/interface.h>
#include "bitbang.h"

// Define our version of the protocol used.  Remote side must match.
//#define PROTOCOL_VERSION        0x01

// Arbitrary limit on host name length.
#define REMOTE_SWD_HOST_MAX     255

// First 4 bits hold the command code.
#define FLAGS_CMD_VERSION       (1<<0)
#define FLAGS_CMD_SERIAL_NUM    (2<<0)
#define FLAGS_CMD_SPEED         (3<<0)     // speed in 'data' field
#define FLAGS_CMD_RESET         (4<<0)     // NRST state in 'data' field
#define FLAGS_CMD_LED           (5<<0)     // on/off in 'data' field
#define FLAGS_CMD_SWITCH_SEQ    (6<<0)
#define FLAGS_CMD_READ_REG      (7<<0)
#define FLAGS_CMD_WRITE_REG     (8<<0)
#define FLAGS_CMD(flags)        (flags & 0x0F)

// Remaining bits are reserved for flags.
#define FLAGS_EXPECT_ACK        (1<<4)
#define FLAGS_EXPECT_DATA       (1<<5)

// The 3 ACK bits.
#define ACK_OK                  (1<<0)
#define ACK_WAIT                (1<<1)
#define ACK_FAULT               (1<<2)

// The TCP/IP packet payload consists of an array of these queued_commands.
// We need another place to store the return data pointers.
struct queued_command {
    uint8_t flags;              // input
    uint8_t cmd;                // input
    uint8_t final_clocks;       // input    FIXME - AP delay clocks
    uint8_t ack;                // output (3 bits)
    uint32_t data;              // input or output.
};

enum block_bool {
	NO_BLOCK,
	BLOCK
};

enum flush_bool {
	NO_FLUSH,
	FLUSH_SEND_BUF
};

static char *remote_swd_host;
static char *remote_swd_port;
static int sockfd;

// The queued commands and a write index.
static struct queued_command queued_commands[128];
static unsigned int queued_commands_idx;

// The caller's pointers for storing response data, and the ACK responses.
static uint32_t* response_data[128];
static uint8_t response_acks[128];

static int remote_swd_run_queue(void);

static int remote_swd_queue(struct queued_command* cmd, uint32_t* response,
        enum flush_bool flush)
{
	queued_commands[queued_commands_idx] = *cmd;
    response_data[queued_commands_idx] = response;

    if(response == NULL)
        LOG_INFO("No response pointer provided!");
    queued_commands_idx++;
	if (flush == FLUSH_SEND_BUF ||
			queued_commands_idx >= ARRAY_SIZE(queued_commands))
		return remote_swd_run_queue();
	return ERROR_OK;
}

static int remote_swd_quit(void)
{
	LOG_INFO("remote_swd interface quit");

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
	LOG_INFO("remote_swd CMD_RESET: trst=%d, srst=%d", trst, srst);

    struct queued_command cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.flags = FLAGS_CMD_RESET;
    cmd.data = srst ? 1 : 0;    /* SWD doesn't have TRST. */

	/* Always flush the send buffer on reset */
	return remote_swd_queue(&cmd, NULL, NO_FLUSH);
}

static int remote_swd_speed(int hz)
{
	LOG_INFO("remote_swd CMD_SPEED: %d Hz", hz);

    struct queued_command command;
    memset(&command, 0, sizeof(command));
    command.flags = FLAGS_CMD_SPEED;
    command.data = hz;
	return remote_swd_queue(&command, NULL, NO_FLUSH);
}

static void remote_swd_write_reg(unsigned char cmd, unsigned int value,
        unsigned int ap_delay_clk)
{
    LOG_INFO("remote_swd CMD_WRITE_REG: cmd=0x%02x, value=0x%08x, ap_delay_clk=%d",
            cmd, value, ap_delay_clk);

    struct queued_command command;
    memset(&command, 0, sizeof(command));
    command.flags = FLAGS_CMD_WRITE_REG;
    command.flags |= FLAGS_EXPECT_ACK;
    command.cmd = cmd | SWD_CMD_START | SWD_CMD_PARK;
    command.data = value;
    command.final_clocks = ap_delay_clk;

	if (remote_swd_queue(&command, NULL, NO_FLUSH) == ERROR_FAIL) {
        LOG_INFO("write_reg failed");
    }
}

static void remote_swd_read_reg(unsigned char cmd, unsigned int *value,
        unsigned int ap_delay_clk)
{
    LOG_INFO("remote_swd CMD_READ_REG: cmd=0x%02x, ap_delay_clk=%d", cmd,
            ap_delay_clk);

    struct queued_command command;
    memset(&command, 0, sizeof(command));
    command.flags = FLAGS_CMD_READ_REG;
    command.flags |= FLAGS_EXPECT_ACK;
    command.flags |= FLAGS_EXPECT_DATA;
    command.cmd = cmd | SWD_CMD_START | SWD_CMD_PARK;
    command.final_clocks = ap_delay_clk;

	if (remote_swd_queue(&command, value, NO_FLUSH) == ERROR_FAIL) {
        LOG_INFO("read_reg failed");
    }
}

static int remote_swd_switch_seq(enum swd_special_seq seq)
{
	LOG_INFO("remote_swd CMD_SWITCH_SEQ: %d", seq);

    struct queued_command command;
    memset(&command, 0, sizeof(command));
    command.flags = FLAGS_CMD_SWITCH_SEQ;
    command.data = seq;

	if (remote_swd_queue(&command, NULL, NO_FLUSH) == ERROR_FAIL)
		return ERROR_FAIL;
    return 0;
}

static int remote_swd_version(unsigned int* value)
{
	LOG_INFO("remote_swd VERSION");

    struct queued_command command;
    memset(&command, 0, sizeof(command));
    command.flags = FLAGS_CMD_VERSION;

	if (remote_swd_queue(&command, value, FLUSH_SEND_BUF) == ERROR_FAIL)
		return ERROR_FAIL;
    return 0;
}

static int remote_swd_serial_number(unsigned int* value)
{
	LOG_INFO("remote_swd SERIAL_NUM");

    struct queued_command command;
    memset(&command, 0, sizeof(command));
    command.flags = FLAGS_CMD_SERIAL_NUM;

	if (remote_swd_queue(&command, value, FLUSH_SEND_BUF) == ERROR_FAIL)
		return ERROR_FAIL;
    return 0;
}

static int remote_swd_init_tcp(void)
{
	struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM };
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
	LOG_INFO("remote_swd_swd_init");
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
        LOG_INFO("Failed initializing socket for remote_swd driver. Error: %d", errno);
		return ret;
    }
    sockfd = ret;

	LOG_INFO("remote_swd driver initialized");

    // Get device version and serial number.
    unsigned int version;
    unsigned int serial_num;
    remote_swd_version(&version);
    remote_swd_serial_number(&serial_num);

    LOG_INFO("Remote version: %u.%u", version >> 8, version & 0xFF);
    LOG_INFO("Remote serial number: %u", serial_num);
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
    // TODO subcommands to set the pin numbers for SWDIO, SWCLK, SRST.
    // Add new CMD to set GPIO pin numbers.
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
	LOG_INFO("Executing %d queued transactions", queued_commands_idx);
	if (queued_commands_idx <= 0)
		return ERROR_OK;

    // TODO - firmware must always send 8 idle clocks at the end of the queue.

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

    // Iterate over the response data, storing the responses into the caller's pointers.
    for(unsigned i=0; i<queued_commands_idx; i++) {
        struct queued_command* cmd = &queued_commands[i];
        struct queued_command* resp = &response[i];

        if(cmd->flags & FLAGS_EXPECT_ACK)
            response_acks[i] = resp->ack;
        if(cmd->flags & FLAGS_EXPECT_DATA) {
            LOG_INFO("Got response data: %08x", resp->data);
            if(response_data[i])
                *response_data[i] = resp->data;
        }
    }

    // TODO - Return ACK response on WAIT/FAULT.  How does this work if multiple commands are queued?

	LOG_DEBUG("SWD run_queue success");
	queued_commands_idx = 0;
	return ERROR_OK;
}

// SWD only.
static const char * const remote_swd_transports[] = { "swd", NULL };

const struct swd_driver remote_swd_ops = {
	.init = remote_swd_swd_init,
	.switch_seq = remote_swd_switch_seq,
	.read_reg = remote_swd_read_reg,
	.write_reg = remote_swd_write_reg,
	.run = remote_swd_run_queue,
};

struct adapter_driver remote_swd_adapter_driver = {
	.name = "remote_swd",
	.transports = remote_swd_transports,
	.commands = remote_swd_command_handlers,
	.init = &remote_swd_init,
	.quit = &remote_swd_quit,
	.speed = &remote_swd_speed,
	.reset = &remote_swd_reset,
	.swd_ops = &remote_swd_ops,
};
