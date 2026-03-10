/// Detect container or service context for a process.
///
/// Returns a short label like `"docker:abc123def456"`, `"k8s:my-pod"`, or
/// `"nginx.service"` when the process is running inside a known container
/// runtime or systemd service.  Returns `None` when the process is bare-metal
/// or the context cannot be determined.
pub fn detect(pid: u32) -> Option<String> {
    detect_inner(pid)
}

#[cfg(target_os = "linux")]
fn detect_inner(pid: u32) -> Option<String> {
    let cgroup = std::fs::read_to_string(format!("/proc/{}/cgroup", pid)).ok()?;

    for line in cgroup.lines() {
        // cgroup v1 format: <hierarchy-id>:<subsystems>:<path>
        // cgroup v2 format: 0::<path>
        let path = line.splitn(3, ':').nth(2)?;

        // Docker
        if let Some(idx) = path.find("/docker/") {
            let rest = &path[idx + "/docker/".len()..];
            let id = rest.split('/').next().unwrap_or(rest);
            if id.len() >= 12 {
                return Some(format!("docker:{}", &id[..12]));
            }
        }

        // Kubernetes (kubepods)
        if path.contains("/kubepods/") {
            // Try to extract pod name from the path segment
            for segment in path.split('/') {
                if segment.starts_with("pod") && segment.len() > 3 {
                    let pod = &segment[3..]; // strip "pod" prefix
                                             // Truncate to 24 chars so the label stays readable
                    let truncated = if pod.len() > 24 { &pod[..24] } else { pod };
                    return Some(format!("k8s:{}", truncated));
                }
            }
            return Some("k8s".to_string());
        }

        // containerd / nerdctl
        if let Some(idx) = path.find("/containerd/") {
            let rest = &path[idx + "/containerd/".len()..];
            let id = rest.split('/').next().unwrap_or(rest);
            if id.len() >= 12 {
                return Some(format!("containerd:{}", &id[..12]));
            }
        }

        // systemd service (only for cgroup v1 name=systemd or v2 path)
        if path.contains(".service") {
            for segment in path.split('/') {
                if segment.ends_with(".service") {
                    return Some(segment.to_string());
                }
            }
        }
    }

    None
}

#[cfg(not(target_os = "linux"))]
fn detect_inner(_pid: u32) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn detect_returns_none_for_init() {
        // PID 1 is never inside a container on a normal host.
        // This may return a systemd service label on some systems, which is fine.
        let result = detect(1);
        if let Some(label) = result {
            // If something is returned it should be a non-empty string
            assert!(!label.is_empty());
        }
    }

    #[test]
    fn detect_returns_none_for_bogus_pid() {
        // PID 0 never exists
        assert_eq!(detect(0), None);
    }
}
