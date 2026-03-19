pub(crate) mod remote_client;
pub(crate) mod user_client;

macro_rules! notify {
    ($tx:expr, $notif:expr) => {
        if $tx.try_send($notif).is_err() {
            tracing::warn!("Notification channel full, dropping notification");
        }
    };
}
pub(crate) use notify;
