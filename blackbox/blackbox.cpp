#include <iostream>
#include <windows.h>

#include <cryptopp/secblock.h>

#include "blackbox.h"

void SetStdinEcho(bool enable)
{
    const HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD        mode;
    GetConsoleMode(hStdin, &mode);

    if (!enable)
        mode &= ~ENABLE_ECHO_INPUT;
    else
        mode |= ENABLE_ECHO_INPUT;

    SetConsoleMode(hStdin, mode);
}
