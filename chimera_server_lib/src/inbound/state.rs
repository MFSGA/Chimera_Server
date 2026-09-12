#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum InboundLifecycleState {
    Prepared,
    Starting,
    Running,
    Draining,
    Stopping,
    Recovering,
    Failed,
}

impl InboundLifecycleState {
    pub(super) fn transition_to(&mut self, next: Self) -> Result<(), &'static str> {
        if !self.can_transition_to(next) {
            return Err("illegal inbound lifecycle transition");
        }
        *self = next;
        Ok(())
    }

    fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Prepared, Self::Starting | Self::Running)
                | (
                    Self::Starting,
                    Self::Prepared | Self::Running | Self::Recovering
                )
                | (
                    Self::Running,
                    Self::Running
                        | Self::Draining
                        | Self::Stopping
                        | Self::Recovering
                        | Self::Failed
                )
                | (Self::Draining, Self::Prepared)
                | (
                    Self::Stopping,
                    Self::Prepared | Self::Starting | Self::Recovering
                )
                | (Self::Recovering, Self::Prepared | Self::Running)
                | (Self::Failed, Self::Running | Self::Stopping)
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PendingInboundLifecycle {
    pub(super) generation: u64,
    pub(super) lifecycle: InboundLifecycleState,
}

#[cfg(test)]
mod tests {
    use super::InboundLifecycleState;

    #[test]
    fn accepts_expected_runtime_transitions() {
        let cases = [
            (
                InboundLifecycleState::Prepared,
                InboundLifecycleState::Starting,
            ),
            (
                InboundLifecycleState::Prepared,
                InboundLifecycleState::Running,
            ),
            (
                InboundLifecycleState::Starting,
                InboundLifecycleState::Running,
            ),
            (
                InboundLifecycleState::Starting,
                InboundLifecycleState::Prepared,
            ),
            (
                InboundLifecycleState::Starting,
                InboundLifecycleState::Recovering,
            ),
            (
                InboundLifecycleState::Running,
                InboundLifecycleState::Draining,
            ),
            (
                InboundLifecycleState::Running,
                InboundLifecycleState::Stopping,
            ),
            (
                InboundLifecycleState::Running,
                InboundLifecycleState::Failed,
            ),
            (
                InboundLifecycleState::Running,
                InboundLifecycleState::Recovering,
            ),
            (
                InboundLifecycleState::Stopping,
                InboundLifecycleState::Starting,
            ),
            (
                InboundLifecycleState::Stopping,
                InboundLifecycleState::Prepared,
            ),
            (
                InboundLifecycleState::Stopping,
                InboundLifecycleState::Recovering,
            ),
            (
                InboundLifecycleState::Recovering,
                InboundLifecycleState::Running,
            ),
            (
                InboundLifecycleState::Recovering,
                InboundLifecycleState::Prepared,
            ),
            (
                InboundLifecycleState::Draining,
                InboundLifecycleState::Prepared,
            ),
            (
                InboundLifecycleState::Failed,
                InboundLifecycleState::Running,
            ),
            (
                InboundLifecycleState::Failed,
                InboundLifecycleState::Stopping,
            ),
        ];

        for (from, to) in cases {
            let mut state = from;
            assert_eq!(state.transition_to(to), Ok(()), "{from:?} -> {to:?}");
            assert_eq!(state, to);
        }
    }

    #[test]
    fn rejects_invalid_transition_without_mutating_state() {
        let mut state = InboundLifecycleState::Prepared;
        assert_eq!(
            state.transition_to(InboundLifecycleState::Failed),
            Err("illegal inbound lifecycle transition")
        );
        assert_eq!(state, InboundLifecycleState::Prepared);
    }
}
