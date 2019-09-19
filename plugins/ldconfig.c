#include <sys/types.h>
#include <sys/wait.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmts.h>
#include "lib/rpmplugin.h"

static rpmRC ldconfig_tsm_post(rpmPlugin plugin, rpmts ts, int res)
{
    int pid = -1;
    siginfo_t info;
    do {
	pid = fork ();
    } while (pid < 0);

    if (pid) {
	info.si_code = 0;
	info.si_status = 0;

	if (waitid (P_PID, pid, &info, WEXITED)) {
	    rpmlog(RPMLOG_DEBUG, "Failed to wait for ldconfig\n");
	}

	if (info.si_code != CLD_EXITED || info.si_status) {
	    rpmlog(RPMLOG_DEBUG, "Bad ldconfig exit code %i and status %i\n", info.si_code, info.si_status);
	}

    } else {
	execlp ("ldconfig", "ldconfig", (char *)NULL);
    }

    return RPMRC_OK;
}

struct rpmPluginHooks_s ldconfig_hooks = {
    .tsm_post = ldconfig_tsm_post,
};
