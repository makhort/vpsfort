//! systemd's own (PID 1) messages about the services in `[sources] services`:
//! `vpsfort-xmpp-bot.service: Main process exited, code=exited, status=78/CONFIG`,
//! `vpsfort-xmpp-bot.service: Failed with result 'exit-code'.`,
//! `vpsfort-xmpp-bot.service: Scheduled restart job, restart counter is at 3.`,
//! `Starting vpsfort-xmpp-bot.service - XMPP Admin Chatbot Service...` and
//! `vpsfort-xmpp-bot.service: Start request repeated too quickly.`

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnitEvent {
    /// The main process ended uncleanly (systemd logs clean exits at debug level only):
    /// `status=78/CONFIG`, `status=9/KILL`.
    Exited { status: String },
    /// The unit entered the failed state: `exit-code`, `signal`, `timeout`, `oom-kill`, ...
    Failed { result: String },
    /// systemd stopped restarting it (`StartLimitBurst` reached).
    GaveUp,
    /// systemd restarts it on its own (`Restart=`), RestartSec after the failure.
    Restarting,
    /// It is being started (by anyone: a timer, `systemctl start`, a dependency).
    Starting,
}

/// The unit a message is about, and what happened to it.
pub fn parse(msg: &str) -> Option<(String, UnitEvent)> {
    // systemd 252+ names the unit: `Starting vpsfort-xmpp-bot.service - Description...`
    if let Some(r) = msg.strip_prefix("Starting ") {
        let unit = r.split_once(" - ")?.0;
        if unit.contains(char::is_whitespace) || !unit.contains('.') {
            return None;
        }
        return Some((unit.chars().filter(|c| !c.is_control()).take(64).collect(), UnitEvent::Starting));
    }
    let (unit, rest) = msg.split_once(": ")?;
    if unit.contains(char::is_whitespace) || !unit.contains('.') {
        return None;
    }
    let event = if let Some(r) = rest.strip_prefix("Main process exited, ") {
        UnitEvent::Exited { status: r.split("status=").nth(1)?.trim_end_matches('.').to_string() }
    } else if let Some(r) = rest.strip_prefix("Failed with result '") {
        UnitEvent::Failed { result: r.split('\'').next()?.to_string() }
    } else if rest.starts_with("Start request repeated too quickly") {
        UnitEvent::GaveUp
    } else if rest.starts_with("Scheduled restart job") {
        UnitEvent::Restarting
    } else {
        return None;
    };
    let clean = |s: &str| s.chars().filter(|c| !c.is_control()).take(64).collect::<String>();
    let event = match event {
        UnitEvent::Exited { status } => UnitEvent::Exited { status: clean(&status) },
        UnitEvent::Failed { result } => UnitEvent::Failed { result: clean(&result) },
        e => e,
    };
    Some((clean(unit), event))
}

/// journald's own word that it dropped lines: `Suppressed 1431 messages from sshd.service`
/// (the unit logged more than its rate limit allows: `RateLimitBurst`, or the unit's own
/// `LogRateLimitBurst=`) and `Missed 12 kernel messages` (the kernel's ring buffer overran
/// before journald read it). The count and the unit (`the kernel` for the latter).
pub fn suppressed(msg: &str) -> Option<(u64, String)> {
    if let Some(rest) = msg.strip_prefix("Suppressed ") {
        let (n, unit) = rest.split_once(" messages from ")?;
        let unit: String = unit.trim_end_matches('.').chars().filter(|c| !c.is_control()).take(64).collect();
        return (!unit.is_empty() && !unit.contains(char::is_whitespace)).then(|| Some((n.parse().ok()?, unit))).flatten();
    }
    let n = msg.strip_prefix("Missed ")?.strip_suffix(" kernel messages")?;
    Some((n.parse().ok()?, "the kernel".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journald_dropped_lines() {
        assert_eq!(suppressed("Suppressed 1431 messages from sshd.service"), Some((1431, "sshd.service".into())));
        assert_eq!(suppressed("Missed 12 kernel messages"), Some((12, "the kernel".into())));
        assert_eq!(suppressed("Suppressed x messages from sshd.service"), None);
        assert_eq!(suppressed("Suppressed 3 messages from two words"), None);
        assert_eq!(suppressed("Journal started"), None);
        assert_eq!(parse("Suppressed 1431 messages from sshd.service"), None, "not a unit event");
    }

    #[test]
    fn parses_unit_messages() {
        assert_eq!(
            parse("vpsfort-xmpp-bot.service: Main process exited, code=exited, status=78/CONFIG"),
            Some(("vpsfort-xmpp-bot.service".into(), UnitEvent::Exited { status: "78/CONFIG".into() }))
        );
        assert_eq!(
            parse("vpsfort-xmpp-bot.service: Main process exited, code=killed, status=9/KILL"),
            Some(("vpsfort-xmpp-bot.service".into(), UnitEvent::Exited { status: "9/KILL".into() }))
        );
        assert_eq!(
            parse("vpsfort-xmpp-bot.service: Failed with result 'exit-code'."),
            Some(("vpsfort-xmpp-bot.service".into(), UnitEvent::Failed { result: "exit-code".into() }))
        );
        assert_eq!(
            parse("vpsfort-xmpp-bot.service: Start request repeated too quickly."),
            Some(("vpsfort-xmpp-bot.service".into(), UnitEvent::GaveUp))
        );
        assert_eq!(parse("vpsfort-xmpp-bot.service: Deactivated successfully."), None);
        assert_eq!(parse("Stopping vpsfort-xmpp-bot.service - XMPP Admin Chatbot Service..."), None);
        assert_eq!(
            parse("vpsfort-xmpp-bot.service: Scheduled restart job, restart counter is at 2."),
            Some(("vpsfort-xmpp-bot.service".into(), UnitEvent::Restarting))
        );
        assert_eq!(
            parse("Starting vpsfort-xmpp-bot.service - XMPP Admin Chatbot Service..."),
            Some(("vpsfort-xmpp-bot.service".into(), UnitEvent::Starting))
        );
        assert_eq!(parse("Starting XMPP Admin Chatbot Service..."), None, "older systemd: no unit name");
        assert_eq!(parse("Started session-5.scope: x"), None);
    }
}
