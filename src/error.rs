//! Mapping Kubernetes API failures onto `sandbox-driver` errors.

use sandbox_driver::{AuthError, Error, ProviderError, ResourceKind, TransportError};

use crate::kubernetes_kind;

/// The HTTP status of an API error response, when the failure is one.
pub(crate) fn status_code(error: &kube::Error) -> Option<u16> {
    match error {
        kube::Error::Api(status) => Some(status.code),
        _ => None,
    }
}

pub(crate) fn is_not_found(error: &kube::Error) -> bool {
    status_code(error) == Some(404)
}

pub(crate) fn is_conflict(error: &kube::Error) -> bool {
    status_code(error) == Some(409)
}

pub(crate) fn is_unauthorized(error: &kube::Error) -> bool {
    status_code(error) == Some(401)
}

/// Converts a Kubernetes failure in `context` into a driver error.
pub(crate) fn kube_error(context: &str, error: kube::Error) -> Error {
    match status_code(&error) {
        Some(401) => Error::Auth(AuthError::new(
            kubernetes_kind(),
            format!(
                "{context}: the cluster rejected the credential (401) after re-reading the kubeconfig"
            ),
        )),
        // An admission refusal for an exceeded ResourceQuota is ALSO a 403
        // Forbidden, but it is capacity, not a missing permission: the same
        // request succeeds once the namespace has room, so it is retryable and
        // must never read as a credential fault (bd-ib-ko5kxf). Only the
        // Status message tells the two apart.
        Some(403) if quota_exceeded(&error).is_some() => {
            let message = quota_exceeded(&error).unwrap_or_default().to_owned();
            let mut provider = ProviderError::with_source(
                kubernetes_kind(),
                format!("{context}: the namespace has no room (403 {message})"),
                error,
            );
            provider.retryable = true;
            provider.code = Some("quota-exceeded".to_owned());
            Error::Provider(provider)
        }
        Some(403) => Error::Auth(AuthError::new(
            kubernetes_kind(),
            format!("{context}: the credential lacks permission (403): {error}"),
        )),
        Some(code) if code >= 500 || code == 429 => {
            let mut provider = ProviderError::with_source(
                kubernetes_kind(),
                format!("{context}: the API server answered {code}"),
                error,
            );
            provider.retryable = true;
            Error::Provider(provider)
        }
        Some(_) => Error::Provider(ProviderError::with_source(
            kubernetes_kind(),
            context.to_owned(),
            error,
        )),
        // A connection the API never accepted, retried until the budget ran
        // out: the cluster is unreachable rather than the sandbox broken, so
        // the caller may retry later.
        None if exhausted_retry(&error).is_some() => {
            let (attempts, elapsed) = exhausted_retry(&error).unwrap_or_default();
            let mut provider = ProviderError::with_source(
                kubernetes_kind(),
                format!(
                    "{context}: the Kubernetes API refused the connection on all {attempts} attempts over {elapsed:.1}s: {error}"
                ),
                error,
            );
            provider.retryable = true;
            provider.code = Some("api-unreachable".to_owned());
            Error::Provider(provider)
        }
        // The source's own text is part of the message: a caller that logs
        // only the message (the worker does) otherwise cannot tell a refused
        // upgrade from a dropped connection.
        None => Error::Transport(TransportError::with_source(
            format!("{context}: reaching the Kubernetes API failed: {error}"),
            error,
        )),
    }
}

/// The Status message of an admission refusal for an exceeded ResourceQuota.
///
/// The API server answers it as 403 Forbidden whose message begins
/// `exceeded quota:` and names the quota, the requested, used and limited
/// amounts, for example `pods "x" is forbidden: exceeded quota: factory-runs,
/// requested: limits.cpu=6, used: limits.cpu=114100m, limited: limits.cpu=120`.
fn quota_exceeded(error: &kube::Error) -> Option<&str> {
    match error {
        kube::Error::Api(status)
            if status.code == 403 && status.message.contains("exceeded quota") =>
        {
            Some(status.message.as_str())
        }
        _ => None,
    }
}

/// The attempts and elapsed seconds of a connect retry that ran out.
fn exhausted_retry(error: &kube::Error) -> Option<(u32, f64)> {
    let kube::Error::Service(service) = error else {
        return None;
    };
    service
        .downcast_ref::<crate::client::ConnectRetryExhausted>()
        .map(|exhausted| (exhausted.attempts, exhausted.elapsed_secs))
}

pub(crate) fn not_found(id: &str) -> Error {
    Error::NotFound {
        resource: ResourceKind::Sandbox,
        id: id.to_owned(),
    }
}

/// A provider error the caller should retry later, such as a sandbox whose
/// node is `NotReady`.
pub(crate) fn unavailable(message: impl Into<String>) -> Error {
    let mut provider = ProviderError::new(kubernetes_kind(), message);
    provider.retryable = true;
    provider.code = Some("unavailable".to_owned());
    Error::Provider(provider)
}

pub(crate) fn provider(message: impl Into<String>) -> Error {
    Error::Provider(ProviderError::new(kubernetes_kind(), message))
}

pub(crate) fn record_io(context: &str, error: std::io::Error) -> Error {
    Error::io(format!("{context} (host-side record)"), error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::core::Status;

    fn forbidden(message: &str) -> kube::Error {
        kube::Error::Api(Status::failure(message, "Forbidden").with_code(403).boxed())
    }

    #[test]
    fn an_exceeded_quota_403_is_retryable_capacity_not_auth() {
        let message = "pods \"petri-01m78kw65m3f-l0\" is forbidden: exceeded quota: factory-runs, \
                       requested: limits.cpu=6, used: limits.cpu=114100m, limited: limits.cpu=120";
        match kube_error("creating the sandbox pod", forbidden(message)) {
            Error::Provider(provider) => {
                assert!(provider.retryable, "a quota refusal is retryable");
                assert_eq!(provider.code.as_deref(), Some("quota-exceeded"));
                for needle in [
                    "factory-runs",
                    "requested: limits.cpu=6",
                    "used: limits.cpu=114100m",
                    "limited: limits.cpu=120",
                ] {
                    assert!(
                        provider.message.contains(needle),
                        "message names {needle}: {}",
                        provider.message
                    );
                }
                assert!(
                    !provider.message.contains("credential"),
                    "{}",
                    provider.message
                );
            }
            other => panic!("expected a retryable provider error, got {other:?}"),
        }
    }

    #[test]
    fn any_other_403_is_still_a_missing_permission() {
        let message = "pods is forbidden: User \"system:serviceaccount:factory:launcher\" cannot create resource \"pods\"";
        match kube_error("creating the sandbox pod", forbidden(message)) {
            Error::Auth(auth) => assert!(
                auth.to_string()
                    .contains("the credential lacks permission (403)"),
                "{auth}"
            ),
            other => panic!("expected an auth error, got {other:?}"),
        }
    }
}
