use crate::domain::UpdatesInfo;

#[cfg(all(target_os = "linux", any(test, feature = "internals")))]
use crate::domain::UpdatePackage;

#[cfg(target_os = "linux")]
mod apk;
#[cfg(target_os = "linux")]
mod apt;
mod common;
#[cfg(target_os = "linux")]
mod dnf;
#[cfg(target_os = "linux")]
mod pacman;
#[cfg(any(target_os = "freebsd", test))]
mod pkg_freebsd;

#[cfg(target_os = "linux")]
pub fn gather_updates() -> Option<UpdatesInfo> {
    gather_linux_updates()
}

#[cfg(target_os = "freebsd")]
pub fn gather_updates() -> Option<UpdatesInfo> {
    gather_freebsd_updates()
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
pub fn gather_updates() -> Option<UpdatesInfo> {
    None
}

#[cfg(target_os = "linux")]
fn gather_linux_updates() -> Option<UpdatesInfo> {
    apt::gather_apt_updates()
        .or_else(dnf::gather_dnf_updates)
        .or_else(pacman::gather_pacman_updates)
        .or_else(pacman::gather_checkupdates)
        .or_else(apk::gather_apk_updates)
}

#[cfg(target_os = "freebsd")]
fn gather_freebsd_updates() -> Option<UpdatesInfo> {
    pkg_freebsd::gather_freebsd_pkg_updates()
}

#[cfg(all(target_os = "linux", any(test, feature = "internals")))]
pub fn parse_apt_upgradable_line_for_tests(line: &str) -> Option<UpdatePackage> {
    apt::parse_apt_upgradable_line(line)
}

#[cfg(all(target_os = "linux", any(test, feature = "internals")))]
pub fn count_dnf_updates_for_tests(output: &str) -> usize {
    dnf::count_dnf_updates(output)
}

#[cfg(all(target_os = "linux", any(test, feature = "internals")))]
pub fn count_apk_updates_for_tests(output: &str) -> usize {
    apk::count_apk_updates(output)
}
