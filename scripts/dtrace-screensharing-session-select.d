#!/usr/bin/dtrace -s

#pragma D option quiet
#pragma D option switchrate=10hz

dtrace:::BEGIN
{
    printf("=== Screen Sharing.app Session Select Trace ===\n");
    printf("Monitoring: Screen Sharing.app\n");
    printf("Timestamp: %Y\n\n", walltimestamp);
}

/* Trace all ScreenSharing framework objc method calls with "session" in the name */
objc$target:ScreenSharing::entry
/strstr(probefunc, "ession") != NULL || strstr(probefunc, "Session") != NULL/
{
    printf("[%6d.%03d] → %s::%s\n",
           timestamp / 1000000000,
           (timestamp / 1000000) % 1000,
           probemod, probefunc);
}

objc$target:ScreenSharing::return
/strstr(probefunc, "ession") != NULL || strstr(probefunc, "Session") != NULL/
{
    printf("[%6d.%03d] ← %s::%s\n",
           timestamp / 1000000000,
           (timestamp / 1000000) % 1000,
           probemod, probefunc);
}

/* Trace VNC socket reads that might be SessionInfo/SessionResult */
syscall::read:return
/execname == "Screen Sharing" && arg1 > 10 && arg1 < 1024/
{
    this->data = (unsigned char*)copyin(arg1, arg1 < 128 ? arg1 : 128);
    this->bodySize = (this->data[0] << 8) | this->data[1];
    this->version = (this->data[2] << 8) | this->data[3];

    printf("[%6d.%03d] READ len=%d: [%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x]\n",
           timestamp / 1000000000,
           (timestamp / 1000000) % 1000,
           arg1,
           this->data[0], this->data[1], this->data[2], this->data[3],
           this->data[4], this->data[5], this->data[6], this->data[7],
           this->data[8], this->data[9], this->data[10], this->data[11],
           this->data[12], this->data[13], this->data[14], this->data[15]);

    /* Try to decode as SessionInfo */
    this->allowedCmds = (this->data[4] << 24) | (this->data[5] << 16) |
                       (this->data[6] << 8) | this->data[7];

    /* SessionInfo: bodySize 12-200, version 0x0100 */
    printf(this->bodySize >= 10 && this->bodySize < 200 && this->version == 0x0100 ?
           "          → SessionInfo: bodySize=%d version=0x%04x allowedCommands=0x%08x\n" : "",
           this->bodySize, this->version, this->allowedCmds);

    /* SessionResult: bodySize=80, version=1 */
    this->status = (this->data[4] << 24) | (this->data[5] << 16) |
                  (this->data[6] << 8) | this->data[7];
    printf(this->bodySize == 80 && this->version == 0x0001 ?
           "          → SessionResult: bodySize=%d version=%d status=%d\n" : "",
           this->bodySize, this->version, this->status);
}

/* Trace VNC socket writes that might be SessionCommand */
syscall::write:entry
/execname == "Screen Sharing" && arg2 > 10 && arg2 < 1024/
{
    this->data = (unsigned char*)copyin(arg1, arg2 < 128 ? arg2 : 128);
    this->bodySize = (this->data[0] << 8) | this->data[1];
    this->version = (this->data[2] << 8) | this->data[3];

    printf("[%6d.%03d] WRITE len=%d: [%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x]\n",
           timestamp / 1000000000,
           (timestamp / 1000000) % 1000,
           arg2,
           this->data[0], this->data[1], this->data[2], this->data[3],
           this->data[4], this->data[5], this->data[6], this->data[7],
           this->data[8], this->data[9], this->data[10], this->data[11],
           this->data[12], this->data[13], this->data[14], this->data[15]);

    /* Try to decode as SessionCommand v1 (bodySize=72) */
    this->command = this->data[10];
    printf(this->bodySize == 72 && this->version == 1 ?
           "          → SessionCommand v1: bodySize=%d command=%d\n" : "",
           this->bodySize, this->command);
}

/* Trace NSAlert/dialog creation */
objc$target:::entry
/execname == "Screen Sharing" && strstr(probefunc, "NSAlert") != NULL/
{
    printf("[%6d.%03d] %s::%s\n",
           timestamp / 1000000000,
           (timestamp / 1000000) % 1000,
           probemod, probefunc);
}

dtrace:::END
{
    printf("\n=== Trace Complete ===\n");
}
