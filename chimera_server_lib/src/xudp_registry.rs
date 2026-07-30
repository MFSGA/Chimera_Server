use std::{collections::HashMap, time::Duration};

use tokio::time::Instant;

pub(crate) const XUDP_GLOBAL_REATTACH_TTL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct XudpAttachment {
    pub(crate) token: u64,
    pub(crate) session_id: u16,
    pub(crate) generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct XudpAttachTransition {
    pub(crate) current: XudpAttachment,
    pub(crate) replaced: Option<XudpAttachment>,
    pub(crate) resumed_detached_session: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct XudpGlobalSessionState {
    attachment: Option<XudpAttachment>,
    expires_at: Option<Instant>,
}

#[derive(Debug, Default)]
pub(crate) struct XudpGlobalRegistry {
    sessions: HashMap<[u8; 8], XudpGlobalSessionState>,
    next_attachment_token: u64,
}

impl XudpGlobalRegistry {
    pub(crate) fn attach(
        &mut self,
        global_id: [u8; 8],
        session_id: u16,
        generation: u64,
        now: Instant,
    ) -> std::io::Result<XudpAttachTransition> {
        if global_id == [0; 8] {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "XUDP GlobalID must not be all zeroes",
            ));
        }
        self.remove_expired_id(global_id, now);

        let token = self.next_attachment_token.checked_add(1).ok_or_else(|| {
            std::io::Error::other("XUDP attachment token counter exhausted")
        })?;
        self.next_attachment_token = token;
        let current = XudpAttachment {
            token,
            session_id,
            generation,
        };

        let previous = self.sessions.insert(
            global_id,
            XudpGlobalSessionState {
                attachment: Some(current),
                expires_at: None,
            },
        );
        Ok(XudpAttachTransition {
            current,
            replaced: previous.and_then(|state| state.attachment),
            resumed_detached_session: previous.is_some_and(|state| {
                state.attachment.is_none()
                    && state.expires_at.is_some_and(|expires_at| expires_at > now)
            }),
        })
    }

    pub(crate) fn detach(
        &mut self,
        global_id: [u8; 8],
        attachment_token: u64,
        now: Instant,
    ) -> bool {
        let Some(state) = self.sessions.get_mut(&global_id) else {
            return false;
        };
        if state.attachment.map(|attachment| attachment.token)
            != Some(attachment_token)
        {
            return false;
        }

        state.attachment = None;
        state.expires_at = Some(now + XUDP_GLOBAL_REATTACH_TTL);
        true
    }

    pub(crate) fn remove_current(
        &mut self,
        global_id: [u8; 8],
        attachment_token: u64,
    ) -> bool {
        let is_current = self
            .sessions
            .get(&global_id)
            .and_then(|state| state.attachment)
            .is_some_and(|attachment| attachment.token == attachment_token);
        if is_current {
            self.sessions.remove(&global_id);
        }
        is_current
    }

    pub(crate) fn current(
        &mut self,
        global_id: [u8; 8],
        now: Instant,
    ) -> Option<XudpAttachment> {
        self.remove_expired_id(global_id, now);
        self.sessions
            .get(&global_id)
            .and_then(|state| state.attachment)
    }

    pub(crate) fn take_expired(&mut self, now: Instant) -> Vec<[u8; 8]> {
        let expired = self
            .sessions
            .iter()
            .filter_map(|(global_id, state)| {
                (state.attachment.is_none()
                    && state.expires_at.is_some_and(|expires_at| expires_at <= now))
                .then_some(*global_id)
            })
            .collect::<Vec<_>>();
        for global_id in &expired {
            self.sessions.remove(global_id);
        }
        expired
    }

    fn remove_expired_id(&mut self, global_id: [u8; 8], now: Instant) {
        let expired = self.sessions.get(&global_id).is_some_and(|state| {
            state.attachment.is_none()
                && state.expires_at.is_some_and(|expires_at| expires_at <= now)
        });
        if expired {
            self.sessions.remove(&global_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GLOBAL_ID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

    #[test]
    fn reattach_replaces_current_attachment() {
        let now = Instant::now();
        let mut registry = XudpGlobalRegistry::default();
        let first = registry
            .attach(GLOBAL_ID, 10, 20, now)
            .expect("attach first XUDP session");
        let second = registry
            .attach(GLOBAL_ID, 11, 21, now)
            .expect("reattach XUDP session");

        assert_eq!(second.replaced, Some(first.current));
        assert!(!second.resumed_detached_session);
        assert_eq!(registry.current(GLOBAL_ID, now), Some(second.current));
    }

    #[test]
    fn stale_detach_does_not_remove_new_attachment() {
        let now = Instant::now();
        let mut registry = XudpGlobalRegistry::default();
        let first = registry
            .attach(GLOBAL_ID, 10, 20, now)
            .expect("attach first XUDP session");
        let second = registry
            .attach(GLOBAL_ID, 11, 21, now)
            .expect("reattach XUDP session");

        assert!(!registry.detach(GLOBAL_ID, first.current.token, now));
        assert_eq!(registry.current(GLOBAL_ID, now), Some(second.current));
    }

    #[test]
    fn detached_session_can_resume_before_expiry() {
        let now = Instant::now();
        let mut registry = XudpGlobalRegistry::default();
        let first = registry
            .attach(GLOBAL_ID, 10, 20, now)
            .expect("attach XUDP session");
        assert!(registry.detach(GLOBAL_ID, first.current.token, now));

        let resumed = registry
            .attach(
                GLOBAL_ID,
                11,
                21,
                now + XUDP_GLOBAL_REATTACH_TTL - Duration::from_millis(1),
            )
            .expect("resume detached XUDP session");
        assert!(resumed.resumed_detached_session);
        assert_eq!(resumed.replaced, None);
    }

    #[test]
    fn detached_session_expires_after_one_minute() {
        let now = Instant::now();
        let mut registry = XudpGlobalRegistry::default();
        let first = registry
            .attach(GLOBAL_ID, 10, 20, now)
            .expect("attach XUDP session");
        assert!(registry.detach(GLOBAL_ID, first.current.token, now));

        assert_eq!(
            registry.take_expired(now + XUDP_GLOBAL_REATTACH_TTL),
            vec![GLOBAL_ID]
        );
        assert_eq!(
            registry.current(GLOBAL_ID, now + XUDP_GLOBAL_REATTACH_TTL),
            None
        );
    }

    #[test]
    fn reattach_at_expiry_starts_a_fresh_session() {
        let now = Instant::now();
        let mut registry = XudpGlobalRegistry::default();
        let first = registry
            .attach(GLOBAL_ID, 10, 20, now)
            .expect("attach XUDP session before expiry boundary");
        assert!(registry.detach(GLOBAL_ID, first.current.token, now));

        let fresh = registry
            .attach(GLOBAL_ID, 11, 21, now + XUDP_GLOBAL_REATTACH_TTL)
            .expect("attach XUDP session at expiry boundary");

        assert!(!fresh.resumed_detached_session);
        assert_eq!(fresh.replaced, None);
        assert_eq!(
            registry.current(GLOBAL_ID, now + XUDP_GLOBAL_REATTACH_TTL),
            Some(fresh.current)
        );
    }

    #[test]
    fn stale_remove_current_does_not_delete_new_attachment() {
        let now = Instant::now();
        let mut registry = XudpGlobalRegistry::default();
        let first = registry
            .attach(GLOBAL_ID, 10, 20, now)
            .expect("attach first XUDP session");
        let second = registry
            .attach(GLOBAL_ID, 11, 21, now)
            .expect("attach replacement XUDP session");

        assert!(!registry.remove_current(GLOBAL_ID, first.current.token));
        assert_eq!(registry.current(GLOBAL_ID, now), Some(second.current));
    }

    #[test]
    fn active_attachment_is_not_removed_by_expiry_scan() {
        let now = Instant::now();
        let mut registry = XudpGlobalRegistry::default();
        let attachment = registry
            .attach(GLOBAL_ID, 10, 20, now)
            .expect("attach active XUDP session");

        assert!(
            registry
                .take_expired(now + XUDP_GLOBAL_REATTACH_TTL * 2)
                .is_empty()
        );
        assert_eq!(
            registry.current(GLOBAL_ID, now + XUDP_GLOBAL_REATTACH_TTL * 2),
            Some(attachment.current)
        );
    }

    #[test]
    fn stale_expiry_deadline_does_not_remove_reattached_session() {
        let now = Instant::now();
        let mut registry = XudpGlobalRegistry::default();
        let first = registry
            .attach(GLOBAL_ID, 10, 20, now)
            .expect("attach first XUDP session");
        assert!(registry.detach(GLOBAL_ID, first.current.token, now));

        let resumed_at = now + XUDP_GLOBAL_REATTACH_TTL / 2;
        let resumed = registry
            .attach(GLOBAL_ID, 11, 21, resumed_at)
            .expect("reattach XUDP session before stale expiry deadline");

        assert!(
            registry
                .take_expired(now + XUDP_GLOBAL_REATTACH_TTL)
                .is_empty()
        );
        assert_eq!(
            registry.current(GLOBAL_ID, now + XUDP_GLOBAL_REATTACH_TTL),
            Some(resumed.current)
        );
    }

    #[test]
    fn expired_attachment_token_cannot_detach_fresh_session() {
        let now = Instant::now();
        let mut registry = XudpGlobalRegistry::default();
        let first = registry
            .attach(GLOBAL_ID, 10, 20, now)
            .expect("attach first XUDP session");
        assert!(registry.detach(GLOBAL_ID, first.current.token, now));

        let fresh = registry
            .attach(GLOBAL_ID, 11, 21, now + XUDP_GLOBAL_REATTACH_TTL)
            .expect("attach fresh XUDP session at expiry boundary");

        assert!(!registry.detach(
            GLOBAL_ID,
            first.current.token,
            now + XUDP_GLOBAL_REATTACH_TTL,
        ));
        assert_eq!(
            registry.current(GLOBAL_ID, now + XUDP_GLOBAL_REATTACH_TTL),
            Some(fresh.current)
        );
    }

    #[test]
    fn attachment_token_exhaustion_preserves_current_session() {
        let now = Instant::now();
        let mut registry = XudpGlobalRegistry::default();
        let current = registry
            .attach(GLOBAL_ID, 10, 20, now)
            .expect("attach current XUDP session");
        registry.next_attachment_token = u64::MAX;

        let error = registry
            .attach(GLOBAL_ID, 11, 21, now)
            .expect_err("exhausted XUDP token counter must fail");

        assert_eq!(error.kind(), std::io::ErrorKind::Other);
        assert!(error.to_string().contains("token counter exhausted"));
        assert_eq!(registry.current(GLOBAL_ID, now), Some(current.current));
    }

    #[test]
    fn zero_global_id_is_rejected() {
        let error = XudpGlobalRegistry::default()
            .attach([0; 8], 1, 1, Instant::now())
            .expect_err("zero XUDP GlobalID must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }
}
