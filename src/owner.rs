//! Which plugin process owns a cleanup pod, and whether it is still alive.
//!
//! A delete that empties a stopped sandbox's workspace creates a short-lived
//! cleanup pod and removes it before returning. When the process serving the
//! delete ends first, nothing would remove that pod; the next provider call
//! recognises it as abandoned by the owner it names.

/// This host's name, as the kernel reports it.
fn host() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|name| name.trim().to_owned())
        .ok()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "unknown-host".to_owned())
}

/// The start time (in clock ticks since boot) of process `pid`, which with
/// the pid identifies one process even across pid reuse.
fn start_ticks(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The command name may hold spaces and parentheses; the fields that
    // follow its closing parenthesis start at field 3 (state), so field 22
    // (starttime) is the twentieth of them.
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(19)?.parse().ok()
}

/// The owner string for a cleanup pod this process creates.
pub(crate) fn this_process() -> String {
    let pid = std::process::id();
    format!("{}/{pid}/{}", host(), start_ticks(pid).unwrap_or(0))
}

/// Whether `owner` names a process on this host that no longer runs. An
/// owner on another host, or one this process cannot parse, is never judged
/// abandoned here.
pub(crate) fn is_abandoned(owner: &str) -> bool {
    let mut parts = owner.rsplitn(3, '/');
    let (Some(ticks), Some(pid), Some(owner_host)) = (parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let (Ok(ticks), Ok(pid)) = (ticks.parse::<u64>(), pid.parse::<u32>()) else {
        return false;
    };
    owner_host == host() && start_ticks(pid) != Some(ticks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_process_is_not_abandoned() {
        assert!(!is_abandoned(&this_process()));
    }

    #[test]
    fn an_ended_process_on_this_host_is_abandoned() {
        let mut child = std::process::Command::new("true").spawn().expect("spawns");
        let pid = child.id();
        let ticks = start_ticks(pid);
        child.wait().expect("waits");
        let owner = format!("{}/{pid}/{}", host(), ticks.unwrap_or(1));
        assert!(is_abandoned(&owner));
    }

    #[test]
    fn a_reused_pid_is_abandoned() {
        let pid = std::process::id();
        let ticks = start_ticks(pid).expect("reads own start time");
        assert!(is_abandoned(&format!("{}/{pid}/{}", host(), ticks + 1)));
    }

    #[test]
    fn another_hosts_process_is_never_abandoned_here() {
        assert!(!is_abandoned("some-other-host/4194304/1"));
    }

    #[test]
    fn an_unparseable_owner_is_never_abandoned() {
        assert!(!is_abandoned("garbage"));
        assert!(!is_abandoned(&format!("{}/x/y", host())));
    }
}
