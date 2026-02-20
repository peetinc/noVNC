#!/usr/bin/dtrace -s

#pragma D option quiet
#pragma D option switchrate=10hz

dtrace:::BEGIN
{
    printf("=== Screen Sharing Socket Trace ===\n");
    printf("Monitoring: SessionSelect + Auto-Reconnect behavior\n\n");
    connect_count = 0;
    last_close = 0;
}

/* Track socket connections */
syscall::connect:entry
/execname == "Screen Sharing"/
{
    connect_count++;
    this->time_since_close = last_close > 0 ?
        (timestamp - last_close) / 1000000 : 0;
}

syscall::connect:entry
/execname == "Screen Sharing" && this->time_since_close > 0/
{
    printf("[%Y] CONNECT attempt #%d (%d ms after close - AUTO RECONNECT)\n",
           walltimestamp, connect_count, this->time_since_close);
}

syscall::connect:entry
/execname == "Screen Sharing" && this->time_since_close == 0/
{
    printf("[%Y] CONNECT attempt #%d\n", walltimestamp, connect_count);
}

syscall::connect:return
/execname == "Screen Sharing"/
{
    printf("[%Y] CONNECT %s (errno=%d)\n",
           walltimestamp, arg1 == 0 ? "SUCCESS" : "FAILED", errno);
}

/* Track socket close/disconnects */
syscall::close:entry
/execname == "Screen Sharing" && arg0 >= 3/
{
    last_close = timestamp;
    printf("[%Y] CLOSE fd=%d (will monitor for auto-reconnect)\n",
           walltimestamp, arg0);
}


/* Track all reads to see protocol flow */
syscall::read:return
/execname == "Screen Sharing" && arg1 >= 12 && arg1 <= 512/
{
    this->len = arg1;
    this->buf = (uint8_t*)copyin(arg0, this->len < 128 ? this->len : 128);
    this->bodySize = (this->buf[0] << 8) | this->buf[1];
    this->version = (this->buf[2] << 8) | this->buf[3];

    printf("[%Y] READ %d bytes: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
           walltimestamp, this->len,
           this->buf[0], this->buf[1], this->buf[2], this->buf[3],
           this->buf[4], this->buf[5], this->buf[6], this->buf[7],
           this->buf[8], this->buf[9], this->buf[10], this->buf[11]);

    this->allowedCmds = (this->buf[4] << 24) | (this->buf[5] << 16) |
                        (this->buf[6] << 8) | this->buf[7];
}

/* Detect SessionInfo */
syscall::read:return
/execname == "Screen Sharing" && arg1 >= 12 && arg1 <= 200 &&
 this->bodySize >= 10 && this->bodySize < 200 && this->version == 0x0100/
{
    printf("  → SessionInfo: bodySize=%d allowedCmds=0x%08x\n",
           this->bodySize, this->allowedCmds);
}

/* Detect SessionResult */
syscall::read:return
/execname == "Screen Sharing" && arg1 > 0 &&
 this->bodySize == 80 && this->version == 1/
{
    printf("  → SessionResult: status=%d\n", this->allowedCmds);
}

/* Track all writes to see commands sent */
syscall::write:entry
/execname == "Screen Sharing" && arg2 >= 12 && arg2 <= 512/
{
    this->len = arg2;
    this->buf = (uint8_t*)copyin(arg1, this->len < 128 ? this->len : 128);
    this->bodySize = (this->buf[0] << 8) | this->buf[1];
    this->version = (this->buf[2] << 8) | this->buf[3];
    this->command = this->buf[10];

    printf("[%Y] WRITE %d bytes: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
           walltimestamp, this->len,
           this->buf[0], this->buf[1], this->buf[2], this->buf[3],
           this->buf[4], this->buf[5], this->buf[6], this->buf[7],
           this->buf[8], this->buf[9], this->buf[10], this->buf[11]);
}

/* Detect SessionCommand */
syscall::write:entry
/execname == "Screen Sharing" && arg2 > 0 &&
 this->bodySize == 72 && this->version == 1/
{
    printf("  → SessionCommand: command=%d ", this->command);
}

syscall::write:entry
/execname == "Screen Sharing" && arg2 > 0 &&
 this->bodySize == 72 && this->version == 1 && this->command == 0/
{
    printf("(RequestConsole)\n");
}

syscall::write:entry
/execname == "Screen Sharing" && arg2 > 0 &&
 this->bodySize == 72 && this->version == 1 && this->command == 1/
{
    printf("(ConnectToConsole)\n");
}

syscall::write:entry
/execname == "Screen Sharing" && arg2 > 0 &&
 this->bodySize == 72 && this->version == 1 && this->command == 2/
{
    printf("(ConnectToVirtualDisplay)\n");
}

/* Detect VNC ServerInit (reconnect after auth) */
syscall::read:return
/execname == "Screen Sharing" && arg1 == 24/
{
    this->buf = (uint8_t*)copyin(arg0, 24);
    this->width = (this->buf[0] << 8) | this->buf[1];
    this->height = (this->buf[2] << 8) | this->buf[3];
    printf("[%Y] ServerInit: %dx%d\n", walltimestamp, this->width, this->height);
}

/* Detect auth attempts (might indicate reconnect) */
syscall::write:entry
/execname == "Screen Sharing" && arg2 == 1/
{
    this->buf = (uint8_t*)copyin(arg1, 1);
    this->val = this->buf[0];
}

syscall::write:entry
/execname == "Screen Sharing" && arg2 == 1 && this->val == 51/
{
    printf("[%Y] Sent auth type selection (type 51/33 RSATunnel)\n", walltimestamp);
}

dtrace:::END
{
    printf("\n=== Trace Complete ===\n");
}
