#[cfg(all(test, feature = "config"))]
mod t {
    use std::{fs, io::Write};
    use tempfile::tempdir;

    #[test]
    fn deny_parent_dir_component() {
        let err = describe_me::load_config_from_path("../etc/describe_me/cfg.toml").unwrap_err();
        assert!(format!("{err}").contains(".."), "doit refuser `..`");
    }

    #[test]
    fn deny_unknown_fields() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("cfg.toml");
        let mut f = fs::File::create(&file).unwrap();
        writeln!(f, r#"[services] include=["sshd.service"] oops=true"#).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let r = describe_me::load_config_from_path(&file);
        assert!(r.is_err(), "champs inconnus doivent être rejetés");
    }

    #[test]
    fn require_0600() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir = tempdir().unwrap();
            let file = dir.path().join("cfg.toml");
            fs::write(&file, r#"[services] include=[]"#).unwrap();
            fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap(); // trop permissif
            let err = describe_me::load_config_from_path(&file).unwrap_err();
            assert!(format!("{err}").contains("chmod 600"));
        }
    }
}
