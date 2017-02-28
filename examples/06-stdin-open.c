#include "ws_capture.h"
#include "ws_dissect.h"

#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>

void timeout(int signo) {
    /* doesn't need to do anything */
}

int main(int argc, char *argv[]) {
    ws_capture_init();
    ws_dissect_init();

    static struct sigaction action = {{0}};
    action.sa_handler = timeout;
    sigaction(SIGALRM, &action, NULL);
    alarm(1);
    int ch = getchar();
    int err = errno;
    alarm(0);
    assert(ch != EOF || (ch == EOF && err == EINTR));

    ws_dissect_finalize();
    ws_capture_finalize();
    return 0;
}


