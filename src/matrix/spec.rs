// Reference spec v1.15

#[derive(Clone, PartialEq)]
pub(crate) enum EndpointType {
    Federation,
    WellKnown,
    LegacyMedia,
}

#[derive(Clone, PartialEq)]
pub(crate) enum AuthType {
    Unauthenticated,
    CheckSignature,
}

#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Action {
    Allow,
    Reject,
}
