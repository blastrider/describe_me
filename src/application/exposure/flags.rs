#[cfg(feature = "config")]
use crate::domain::ExposureConfig;

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    struct ExposureFlags: u16 {
        const HOSTNAME = 1 << 0;
        const OS = 1 << 1;
        const KERNEL = 1 << 2;
        const SERVICES = 1 << 3;
        const DISK = 1 << 4;
        const SOCKETS = 1 << 5;
        const UPDATES = 1 << 6;
        const NETWORK = 1 << 7;
        const EXTENSIONS = 1 << 8;
        const CONTAINERS_SUMMARY = 1 << 9;
        const CONTAINERS_DETAILS = 1 << 10;
        const ALL = Self::HOSTNAME.bits()
            | Self::OS.bits()
            | Self::KERNEL.bits()
            | Self::SERVICES.bits()
            | Self::DISK.bits()
            | Self::SOCKETS.bits()
            | Self::UPDATES.bits()
            | Self::NETWORK.bits()
            | Self::EXTENSIONS.bits()
            | Self::CONTAINERS_SUMMARY.bits()
            | Self::CONTAINERS_DETAILS.bits();
    }
}

/// Builder centralizing aggregation from config/CLI/web into an [`Exposure`].
#[derive(Debug, Clone)]
pub struct ExposureBuilder {
    flags: ExposureFlags,
    redacted: bool,
}

impl ExposureBuilder {
    pub fn new() -> Self {
        Self {
            flags: ExposureFlags::empty(),
            redacted: true,
        }
    }

    pub fn from_exposure(exposure: Exposure) -> Self {
        Self {
            flags: exposure.flags,
            redacted: exposure.redacted,
        }
    }

    #[cfg(feature = "config")]
    pub fn from_config(cfg: &ExposureConfig) -> Self {
        let mut builder = Self::new();
        builder.apply_config(cfg);
        builder
    }

    #[cfg(feature = "config")]
    pub fn apply_config(&mut self, cfg: &ExposureConfig) {
        let overrides = ExposureOverrides::from_flags(cfg);
        self.apply_overrides(&overrides);
        self.redacted &= cfg.redacted;
    }

    /// Apply explicit overrides (CLI/web).
    pub fn apply_overrides(&mut self, overrides: &ExposureOverrides) {
        if overrides.expose_all {
            self.flags = ExposureFlags::ALL;
            self.redacted = false;
            return;
        }

        self.flags
            .set(ExposureFlags::HOSTNAME, overrides.expose_hostname);
        self.flags.set(ExposureFlags::OS, overrides.expose_os);
        self.flags
            .set(ExposureFlags::KERNEL, overrides.expose_kernel);
        self.flags
            .set(ExposureFlags::SERVICES, overrides.expose_services);
        self.flags
            .set(ExposureFlags::DISK, overrides.expose_disk_partitions);
        self.flags
            .set(ExposureFlags::NETWORK, overrides.expose_network_traffic);
        self.flags.set(
            ExposureFlags::CONTAINERS_SUMMARY,
            overrides.expose_containers_summary,
        );
        if overrides.expose_containers_details {
            self.flags.insert(ExposureFlags::CONTAINERS_DETAILS);
            self.flags.insert(ExposureFlags::CONTAINERS_SUMMARY);
        }
        self.flags
            .set(ExposureFlags::UPDATES, overrides.expose_updates);
        self.flags
            .set(ExposureFlags::EXTENSIONS, overrides.expose_extensions);
        self.flags
            .set(ExposureFlags::SOCKETS, overrides.expose_listening_sockets);

        if overrides.no_redacted {
            self.redacted = false;
        }
    }

    /// Apply capture-mode implications (sockets, network, containers).
    pub fn apply_capture(&mut self, ctx: ExposureCaptureContext) {
        if ctx.net_listen {
            self.flags.insert(ExposureFlags::SOCKETS);
        }
        if ctx.net_traffic {
            self.flags.insert(ExposureFlags::NETWORK);
        }
        if ctx.containers {
            self.flags.insert(ExposureFlags::CONTAINERS_DETAILS);
            self.flags.insert(ExposureFlags::CONTAINERS_SUMMARY);
        }
    }

    pub fn build(self) -> Exposure {
        Exposure {
            flags: self.flags,
            redacted: self.redacted,
        }
    }
}

impl Default for ExposureBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Explicit exposure overrides (CLI/web flags).
#[derive(Debug, Clone, Copy, Default)]
pub struct ExposureOverrides {
    pub expose_hostname: bool,
    pub expose_os: bool,
    pub expose_kernel: bool,
    pub expose_services: bool,
    pub expose_disk_partitions: bool,
    pub expose_network_traffic: bool,
    pub expose_containers_summary: bool,
    pub expose_containers_details: bool,
    pub expose_updates: bool,
    pub expose_extensions: bool,
    pub expose_all: bool,
    pub no_redacted: bool,
    pub expose_listening_sockets: bool,
}

/// Shared source for exposure flags (CLI, web, config).
pub trait ExposureFlagSource {
    fn expose_hostname(&self) -> bool;
    fn expose_os(&self) -> bool;
    fn expose_kernel(&self) -> bool;
    fn expose_services(&self) -> bool;
    fn expose_disk_partitions(&self) -> bool;
    fn expose_network_traffic(&self) -> bool;
    fn expose_containers_summary(&self) -> bool;
    fn expose_containers_details(&self) -> bool;
    fn expose_updates(&self) -> bool;
    fn expose_extensions(&self) -> bool;
    fn expose_all(&self) -> bool;
    fn no_redacted(&self) -> bool {
        false
    }
    fn expose_listening_sockets(&self) -> bool {
        false
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! impl_exposure_flag_source {
    (@value $this:ident $base:ident { const($value:expr) }) => {{
        let _ = &$this;
        let _ = &$base;
        $value
    }};
    (@value $this:ident $base:ident { this_field($field:ident) }) => {{
        let _ = &$base;
        $this.$field
    }};
    (@value $this:ident $base:ident { base_field($field:ident) }) => {{
        let _ = &$this;
        $base.$field
    }};
    (@value $this:ident $base:ident { not_this_field($field:ident) }) => {{
        let _ = &$base;
        !$this.$field
    }};
    (@value $this:ident $base:ident { not_base_field($field:ident) }) => {{
        let _ = &$this;
        !$base.$field
    }};
    (
        $ty:ty,
        base: this,
        expose_all: $expose_all:tt,
        no_redacted: $no_redacted:tt,
        expose_listening_sockets: $expose_listening_sockets:tt $(,)?
    ) => {
        impl $crate::ExposureFlagSource for $ty {
            fn expose_hostname(&self) -> bool {
                let base = self;
                base.expose_hostname
            }

            fn expose_os(&self) -> bool {
                let base = self;
                base.expose_os
            }

            fn expose_kernel(&self) -> bool {
                let base = self;
                base.expose_kernel
            }

            fn expose_services(&self) -> bool {
                let base = self;
                base.expose_services
            }

            fn expose_disk_partitions(&self) -> bool {
                let base = self;
                base.expose_disk_partitions
            }

            fn expose_network_traffic(&self) -> bool {
                let base = self;
                base.expose_network_traffic
            }

            fn expose_containers_summary(&self) -> bool {
                let base = self;
                base.expose_containers_summary
            }

            fn expose_containers_details(&self) -> bool {
                let base = self;
                base.expose_containers_details
            }

            fn expose_updates(&self) -> bool {
                let base = self;
                base.expose_updates
            }

            fn expose_extensions(&self) -> bool {
                let base = self;
                base.expose_extensions
            }

            fn expose_all(&self) -> bool {
                let this = self;
                let base = self;
                $crate::impl_exposure_flag_source!(@value this base $expose_all)
            }

            fn no_redacted(&self) -> bool {
                let this = self;
                let base = self;
                $crate::impl_exposure_flag_source!(@value this base $no_redacted)
            }

            fn expose_listening_sockets(&self) -> bool {
                let this = self;
                let base = self;
                $crate::impl_exposure_flag_source!(@value this base $expose_listening_sockets)
            }
        }
    };
    (
        $ty:ty,
        base: field($base_field:ident),
        expose_all: $expose_all:tt,
        no_redacted: $no_redacted:tt,
        expose_listening_sockets: $expose_listening_sockets:tt $(,)?
    ) => {
        impl $crate::ExposureFlagSource for $ty {
            fn expose_hostname(&self) -> bool {
                let base = self.$base_field;
                base.expose_hostname
            }

            fn expose_os(&self) -> bool {
                let base = self.$base_field;
                base.expose_os
            }

            fn expose_kernel(&self) -> bool {
                let base = self.$base_field;
                base.expose_kernel
            }

            fn expose_services(&self) -> bool {
                let base = self.$base_field;
                base.expose_services
            }

            fn expose_disk_partitions(&self) -> bool {
                let base = self.$base_field;
                base.expose_disk_partitions
            }

            fn expose_network_traffic(&self) -> bool {
                let base = self.$base_field;
                base.expose_network_traffic
            }

            fn expose_containers_summary(&self) -> bool {
                let base = self.$base_field;
                base.expose_containers_summary
            }

            fn expose_containers_details(&self) -> bool {
                let base = self.$base_field;
                base.expose_containers_details
            }

            fn expose_updates(&self) -> bool {
                let base = self.$base_field;
                base.expose_updates
            }

            fn expose_extensions(&self) -> bool {
                let base = self.$base_field;
                base.expose_extensions
            }

            fn expose_all(&self) -> bool {
                let this = self;
                let base = self.$base_field;
                $crate::impl_exposure_flag_source!(@value this base $expose_all)
            }

            fn no_redacted(&self) -> bool {
                let this = self;
                let base = self.$base_field;
                $crate::impl_exposure_flag_source!(@value this base $no_redacted)
            }

            fn expose_listening_sockets(&self) -> bool {
                let this = self;
                let base = self.$base_field;
                $crate::impl_exposure_flag_source!(@value this base $expose_listening_sockets)
            }
        }
    };
}

impl ExposureOverrides {
    /// Build explicit overrides from a flag source (CLI, web).
    pub fn from_flags(flags: &impl ExposureFlagSource) -> Self {
        Self {
            expose_hostname: flags.expose_hostname(),
            expose_os: flags.expose_os(),
            expose_kernel: flags.expose_kernel(),
            expose_services: flags.expose_services(),
            expose_disk_partitions: flags.expose_disk_partitions(),
            expose_network_traffic: flags.expose_network_traffic(),
            expose_containers_summary: flags.expose_containers_summary(),
            expose_containers_details: flags.expose_containers_details(),
            expose_updates: flags.expose_updates(),
            expose_extensions: flags.expose_extensions(),
            expose_all: flags.expose_all(),
            no_redacted: flags.no_redacted(),
            expose_listening_sockets: flags.expose_listening_sockets(),
        }
    }
}

#[cfg(feature = "config")]
impl_exposure_flag_source!(
    ExposureConfig,
    base: this,
    expose_all: { const(false) },
    no_redacted: { not_this_field(redacted) },
    expose_listening_sockets: { this_field(expose_listening_sockets) },
);

/// Capture context that forces exposure for some fields (sockets, network, containers).
#[derive(Debug, Clone, Copy, Default)]
pub struct ExposureCaptureContext {
    pub net_listen: bool,
    pub net_traffic: bool,
    pub containers: bool,
}

#[derive(Debug, Copy, Clone)]
pub struct Exposure {
    flags: ExposureFlags,
    /// When `true`, sensitive fields are redacted (safe-by-default). Can be opted-out explicitly,
    /// which may leak hostname, kernel version or service names.
    pub redacted: bool,
}

impl Default for Exposure {
    fn default() -> Self {
        Self {
            flags: ExposureFlags::empty(),
            redacted: true,
        }
    }
}

impl Exposure {
    pub fn all() -> Self {
        Self {
            flags: ExposureFlags::ALL,
            redacted: false,
        }
    }

    pub fn merge(&mut self, other: Self) {
        self.flags |= other.flags;
        self.redacted |= other.redacted;
    }

    pub fn is_all(&self) -> bool {
        self.flags.contains(ExposureFlags::ALL)
    }

    pub fn hostname(&self) -> bool {
        self.flags.contains(ExposureFlags::HOSTNAME)
    }

    pub fn set_hostname(&mut self, value: bool) {
        self.flags.set(ExposureFlags::HOSTNAME, value);
    }

    pub fn os(&self) -> bool {
        self.flags.contains(ExposureFlags::OS)
    }

    pub fn set_os(&mut self, value: bool) {
        self.flags.set(ExposureFlags::OS, value);
    }

    pub fn kernel(&self) -> bool {
        self.flags.contains(ExposureFlags::KERNEL)
    }

    pub fn set_kernel(&mut self, value: bool) {
        self.flags.set(ExposureFlags::KERNEL, value);
    }

    pub fn services(&self) -> bool {
        self.flags.contains(ExposureFlags::SERVICES)
    }

    pub fn set_services(&mut self, value: bool) {
        self.flags.set(ExposureFlags::SERVICES, value);
    }

    pub fn disk_partitions(&self) -> bool {
        self.flags.contains(ExposureFlags::DISK)
    }

    pub fn set_disk_partitions(&mut self, value: bool) {
        self.flags.set(ExposureFlags::DISK, value);
    }

    pub fn listening_sockets(&self) -> bool {
        self.flags.contains(ExposureFlags::SOCKETS)
    }

    pub fn set_listening_sockets(&mut self, value: bool) {
        self.flags.set(ExposureFlags::SOCKETS, value);
    }

    pub fn updates(&self) -> bool {
        self.flags.contains(ExposureFlags::UPDATES)
    }

    pub fn set_updates(&mut self, value: bool) {
        self.flags.set(ExposureFlags::UPDATES, value);
    }

    pub fn network_traffic(&self) -> bool {
        self.flags.contains(ExposureFlags::NETWORK)
    }

    pub fn set_network_traffic(&mut self, value: bool) {
        self.flags.set(ExposureFlags::NETWORK, value);
    }

    pub fn containers_summary(&self) -> bool {
        self.flags.contains(ExposureFlags::CONTAINERS_SUMMARY)
            || self.flags.contains(ExposureFlags::CONTAINERS_DETAILS)
    }

    pub fn set_containers_summary(&mut self, value: bool) {
        self.flags.set(ExposureFlags::CONTAINERS_SUMMARY, value);
    }

    pub fn containers_details(&self) -> bool {
        self.flags.contains(ExposureFlags::CONTAINERS_DETAILS)
    }

    pub fn set_containers_details(&mut self, value: bool) {
        self.flags.set(ExposureFlags::CONTAINERS_DETAILS, value);
        if value {
            self.set_containers_summary(true);
        }
    }

    pub fn extensions(&self) -> bool {
        self.flags.contains(ExposureFlags::EXTENSIONS)
    }

    pub fn set_extensions(&mut self, value: bool) {
        self.flags.set(ExposureFlags::EXTENSIONS, value);
    }
}

#[cfg(feature = "config")]
impl From<&ExposureConfig> for Exposure {
    fn from(cfg: &ExposureConfig) -> Self {
        ExposureBuilder::from_config(cfg).build()
    }
}
