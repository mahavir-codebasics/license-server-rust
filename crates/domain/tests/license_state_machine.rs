//! License state-machine unit tests. Pure logic — no I/O.

use license_domain::*;
use std::time::Duration;
use time::OffsetDateTime;
use uuid::Uuid;

fn new_license() -> License {
    let aid = AccountId(Uuid::now_v7());
    let pid = ProductId(Uuid::now_v7());
    let poid = PolicyId(Uuid::now_v7());
    License::new(aid, pid, poid)
}

#[test]
fn fresh_license_is_active_and_valid() {
    let l = new_license();
    assert_eq!(l.state, LicenseState::Active);
    assert!(l.validate_for_use(OffsetDateTime::now_utc()).is_ok());
}

#[test]
fn suspend_then_reinstate_round_trip() {
    let mut l = new_license();
    l.suspend().unwrap();
    assert_eq!(l.state, LicenseState::Suspended);
    // a suspended license is not valid for use
    assert!(l.validate_for_use(OffsetDateTime::now_utc()).is_err());
    l.reinstate().unwrap();
    assert_eq!(l.state, LicenseState::Active);
}

#[test]
fn cannot_suspend_already_suspended() {
    let mut l = new_license();
    l.suspend().unwrap();
    assert!(l.suspend().is_err());
}

#[test]
fn revoke_is_terminal() {
    let mut l = new_license();
    l.revoke().unwrap();
    assert_eq!(l.state, LicenseState::Revoked);
    // cannot reinstate a revoked license
    assert!(l.reinstate().is_err());
    // cannot renew a revoked license
    assert!(l.renew(Duration::from_secs(3600)).is_err());
    // double revoke is an error
    assert!(l.revoke().is_err());
}

#[test]
fn renew_extends_or_sets_expiry() {
    let mut l = new_license();
    assert!(l.expiry.is_none());
    l.renew(Duration::from_secs(3600)).unwrap();
    let first = l.expiry.unwrap();
    // renewing again should base off the existing expiry (not now), so the
    // new expiry is strictly later than the first.
    l.renew(Duration::from_secs(3600)).unwrap();
    assert!(l.expiry.unwrap() > first);
}

#[test]
fn renew_revives_expired_license() {
    let mut l = new_license();
    l.expire();
    assert_eq!(l.state, LicenseState::Expired);
    l.renew(Duration::from_secs(3600)).unwrap();
    assert_eq!(l.state, LicenseState::Active);
}

#[test]
fn increment_usage_respects_max_uses() {
    let mut l = new_license();
    l.max_uses = Some(3);
    l.increment_usage(2).unwrap();
    assert_eq!(l.uses, 2);
    l.increment_usage(1).unwrap();
    assert_eq!(l.uses, 3);
    // one more would exceed max_uses
    assert!(l.increment_usage(1).is_err());
    assert_eq!(l.uses, 3); // unchanged on error
}

#[test]
fn decrement_and_reset_usage() {
    let mut l = new_license();
    l.max_uses = Some(10);
    l.increment_usage(5).unwrap();
    l.decrement_usage(2);
    assert_eq!(l.uses, 3);
    l.decrement_usage(100); // saturating
    assert_eq!(l.uses, 0);
    l.increment_usage(4).unwrap();
    l.reset_usage();
    assert_eq!(l.uses, 0);
}

#[test]
fn expired_license_fails_validation() {
    let mut l = new_license();
    l.expiry = Some(OffsetDateTime::now_utc() - Duration::from_secs(60));
    assert!(l.validate_for_use(OffsetDateTime::now_utc()).is_err());
}

#[test]
fn check_in_resets_overdue_counter() {
    let mut l = new_license();
    l.overdue_check_ins = 5;
    l.check_in(Duration::from_secs(60));
    assert_eq!(l.overdue_check_ins, 0);
    assert!(l.last_check_in.is_some());
    assert!(l.next_check_in.is_some());
}

#[test]
fn check_in_sets_next_window_in_the_future() {
    let mut l = new_license();
    let now = OffsetDateTime::now_utc();
    l.check_in(Duration::from_secs(3600));
    assert!(l.next_check_in.unwrap() > now);
}

#[test]
fn machine_heartbeat_evaluates_dead_correctly() {
    use license_domain::Machine;
    let aid = AccountId(Uuid::now_v7());
    let lid = LicenseId(Uuid::now_v7());
    let mut m = Machine::new(aid, lid, "fp-abc");
    m.ping(Duration::from_secs(60));
    // immediately after ping, heartbeat is alive
    let now = OffsetDateTime::now_utc();
    assert_eq!(m.evaluate_heartbeat(now), HeartbeatStatus::Alive);
    // after the window elapses, it should be dead
    let later = now + Duration::from_secs(120);
    assert_eq!(m.evaluate_heartbeat(later), HeartbeatStatus::Dead);
}

#[test]
fn machine_always_revive_resurrects_dead() {
    use license_domain::Machine;
    let aid = AccountId(Uuid::now_v7());
    let lid = LicenseId(Uuid::now_v7());
    let mut m = Machine::new(aid, lid, "fp-xyz");
    m.resurrection_strategy = ResurrectionStrategy::AlwaysRevive;
    m.state = MachineState::Dead;
    m.ping(Duration::from_secs(60));
    assert_eq!(m.state, MachineState::Active);
}

#[test]
fn membership_admin_check() {
    assert!(MembershipRole::Owner.is_admin());
    assert!(MembershipRole::Admin.is_admin());
    assert!(!MembershipRole::Developer.is_admin());
    assert!(!MembershipRole::Viewer.is_admin());
}

#[test]
fn id_round_trip_serialization() {
    let id = LicenseId::now();
    let s = id.to_string();
    let parsed: LicenseId = s.parse().unwrap();
    assert_eq!(id, parsed);
    // serde round-trip
    let json = serde_json::to_string(&id).unwrap();
    // should be a quoted uuid string
    assert!(json.starts_with('"'));
    let back: LicenseId = serde_json::from_str(&json).unwrap();
    assert_eq!(id, back);
}
