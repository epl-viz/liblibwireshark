#include "ws_capture.h"
#include "ws_dissect.h"

#include <assert.h>
#include <errno.h>
#include <signal.h>

#include "defs.h"

void timeout(int signo) {
    (void)signo;
    /* doesn't need to do anything */
}

int main() {
    ws_capture_init();
    ws_dissect_init();
#ifdef _WIN32
    puts("Test not supported on Windows");
    return 0;
#else

    static struct sigaction action;
    memset(&action, 0, sizeof(struct sigaction));
    action.sa_handler = timeout;
    sigaction(SIGALRM, &action, NULL);
    alarm(1);
    int ch = getchar();
    int err = errno;
    alarm(0);
    assert(ch != EOF || (ch == EOF && err == EINTR));
#endif

    ws_dissect_finalize();
    ws_capture_finalize();
    return 0;
}


