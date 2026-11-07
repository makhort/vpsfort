//! The instance template (vpsfort-xmpp-bot@.service, one more admin bot per domain) is the admin
//! unit with its own paths: the user, the restart policy, the hardening and the memory limits
//! must stay the same in both.

fn unit(name: &str) -> String {
    std::fs::read_to_string(format!("{}/deploy/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

/// The unit's lines from `ExecStart=` on, and its `User=` and `Group=` lines.
fn shared(text: &str) -> (Vec<&str>, Vec<&str>) {
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.iter().position(|l| l.starts_with("ExecStart=")).expect("ExecStart=");
    let ids = lines.iter().copied().filter(|l| l.starts_with("User=") || l.starts_with("Group=")).collect();
    (lines[start..].to_vec(), ids)
}

#[test]
fn the_instance_template_is_the_admin_unit_with_its_own_paths() {
    let (admin, template) = (unit("vpsfort-xmpp-bot.service"), unit("vpsfort-xmpp-bot@.service"));
    assert_eq!(shared(&admin), shared(&template), "vpsfort-xmpp-bot@.service differs from vpsfort-xmpp-bot.service");
    for line in [
        "WorkingDirectory=/opt/vpsfort-xmpp-bot/instances/%i",
        "Environment=BOT_STATE_PATH=/opt/vpsfort-xmpp-bot/instances/%i/state.json",
        "Environment=LOG_DIR=/var/log/vpsfort-xmpp-bot/%i",
        "EnvironmentFile=/opt/vpsfort-xmpp-bot/instances/%i/config.env",
    ] {
        assert!(template.lines().any(|l| l == line), "{line}");
    }
    // the instance's defaults come first: its config.env overrides them
    let pos = |p: &str| template.lines().position(|l| l.starts_with(p)).unwrap();
    assert!(pos("Environment=") < pos("EnvironmentFile="));
}
