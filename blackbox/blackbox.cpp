#include "blackbox.h"

#include <iostream>
#include <windows.h>

#include <cryptopp/cryptlib.h>
#include <cryptopp/secblock.h>

void SetStdinEcho(bool enable)
{
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD  mode;
    GetConsoleMode(hStdin, &mode);

    if (!enable)
        mode &= ~ENABLE_ECHO_INPUT;
    else
        mode |= ENABLE_ECHO_INPUT;

    SetConsoleMode(hStdin, mode);
}
