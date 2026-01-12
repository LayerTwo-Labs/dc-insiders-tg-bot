use std::{str::FromStr, sync::LazyLock};

use bitcoin::bip32::Xpub;
use futures::{FutureExt as _, future::Either};
use teloxide::{
    requests::{HasPayload, Request as _, Requester},
    types::{ChatId, UpdateId as UpdateSeqId},
};

fn set_tracing_subscriber() -> anyhow::Result<()> {
    use std::borrow::Cow;
    use tracing_subscriber::filter::{Builder, EnvFilter};
    const DEFAULT_DIRECTIVES: &str = "info,dc_insiders_tg_bot=debug";
    let directives = match std::env::var(EnvFilter::DEFAULT_ENV) {
        Ok(env_directives) => {
            Cow::Owned(format!("{DEFAULT_DIRECTIVES},{env_directives}"))
        }
        Err(std::env::VarError::NotPresent) => {
            Cow::Borrowed(DEFAULT_DIRECTIVES)
        }
        Err(err) => return Err(err.into()),
    };
    let env_filter = Builder::default().parse(directives)?;
    tracing_subscriber::fmt().with_env_filter(env_filter).init();
    Ok(())
}

static SECP256K1: LazyLock<
    bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>,
> = LazyLock::new(bitcoin::secp256k1::Secp256k1::new);

/// Generate a unique receiving address for a user
fn generate_signet_addr(
    xpub: &Xpub,
    user_id: teloxide::types::UserId,
) -> anyhow::Result<bitcoin::Address> {
    let low_62_bits: u64 = user_id.0 & (u64::MAX >> 2);
    let low_31_bits: u32 = (user_id.0 & (u64::MAX >> (u64::BITS - 31))) as u32;
    let mid_31_bits: u32 = (low_62_bits >> 31) as u32;
    let hi_2_bits: u32 = (user_id.0 >> 62) as u32;
    let derivation_path = [low_31_bits, mid_31_bits, hi_2_bits]
        .map(|index| bitcoin::bip32::ChildNumber::Normal { index });
    let child_xpub = xpub.derive_pub(&SECP256K1, &derivation_path)?;
    let child_addr =
        bitcoin::Address::p2pkh(child_xpub.to_pub(), bitcoin::Network::Signet);
    Ok(child_addr)
}

async fn user_is_approved(
    xpub: &Xpub,
    electrs_rest_api_url: &str,
    user_id: teloxide::types::UserId,
) -> anyhow::Result<bool> {
    let signet_addr = generate_signet_addr(xpub, user_id)?;
    let endpoint = format!("{electrs_rest_api_url}/address/{signet_addr}/utxo");
    let resp = reqwest::Client::new().get(endpoint).send().await?;
    let utxos: Vec<serde_json::Value> = resp.json().await?;
    Ok(!utxos.is_empty())
}

async fn upgrade_user_permissions(
    tg_bot: &teloxide::Bot,
    chat_id: ChatId,
    user_id: teloxide::types::UserId,
) -> anyhow::Result<()> {
    use teloxide::types::ChatPermissions;
    let permissions = teloxide::types::ChatPermissions::empty()
        | ChatPermissions::SEND_MESSAGES
        | ChatPermissions::SEND_POLLS
        | ChatPermissions::SEND_OTHER_MESSAGES
        | ChatPermissions::ADD_WEB_PAGE_PREVIEWS
        | ChatPermissions::SEND_MEDIA_MESSAGES;
    let _: teloxide::types::True = tg_bot
        .restrict_chat_member(chat_id, user_id, permissions)
        .with_payload_mut(|payload| {
            payload.use_independent_chat_permissions = Some(true)
        })
        .send()
        .await?;
    Ok(())
}

// TODO: handle banned users, already approved users
async fn handle_chat_join_request(
    tg_bot: &teloxide::Bot,
    xpub: &Xpub,
    join_request: &teloxide::types::ChatJoinRequest,
) -> anyhow::Result<()> {
    let user = &join_request.from;
    let signet_addr = generate_signet_addr(xpub, user.id)?;
    let msg = format!(
        "Welcome to DC\\-Insiders\\! Reply in this DM chat to be added to \
         the group\\. You will be restricted from posting mentions, \
         links, attachments, and media\\. You can remove this restriction \
         by sending 1 Signet coin to `{}`, and sending a message in this \
         DM chat\\.",
        signet_addr,
    );
    let _msg: teloxide::types::Message = tg_bot
        .send_message(join_request.user_chat_id, msg)
        .with_payload_mut(|send_message| {
            send_message.parse_mode =
                Some(teloxide::types::ParseMode::MarkdownV2)
        })
        .send()
        .await?;
    tracing::trace!(
        user_id=%user.id,
        username=user.username,
        first_name=%user.first_name,
        last_name=user.last_name,
        %signet_addr,
        "welcome message sent successfully",
    );
    Ok(())
}

const GROUP_CHAT_ID: ChatId = ChatId(-1003587331795);

async fn handle_dm(
    tg_bot: &teloxide::Bot,
    xpub: &Xpub,
    electrs_rest_api_url: &str,
    msg_sender: &teloxide::types::User,
) -> anyhow::Result<()> {
    tracing::trace!(
        user_id=%msg_sender.id,
        username=msg_sender.username,
        first_name=%msg_sender.first_name,
        last_name=msg_sender.last_name,
        "approving chat join request"
    );
    let _: teloxide::types::True = tg_bot
        .approve_chat_join_request(GROUP_CHAT_ID, msg_sender.id)
        .send()
        .await?;
    tracing::info!(
        user_id=%msg_sender.id,
        username=msg_sender.username,
        first_name=%msg_sender.first_name,
        last_name=msg_sender.last_name,
        "approved chat join request"
    );
    if user_is_approved(xpub, electrs_rest_api_url, msg_sender.id).await? {
        let () = upgrade_user_permissions(tg_bot, GROUP_CHAT_ID, msg_sender.id)
            .await?;
        tracing::trace!(
            user_id=%msg_sender.id,
            username=msg_sender.username,
            first_name=%msg_sender.first_name,
            last_name=msg_sender.last_name,
            "upgraded permissions"
        );
    }
    Ok(())
}

fn msg_entity_is_restricted_content(
    msg_entity_kind: &teloxide::types::MessageEntityKind,
) -> bool {
    use teloxide::types::MessageEntityKind;
    matches!(
        msg_entity_kind,
        MessageEntityKind::Email
            | MessageEntityKind::Mention
            | MessageEntityKind::TextLink { url: _ }
            | MessageEntityKind::TextMention { user: _ }
            | MessageEntityKind::Url
    )
}

fn msg_contains_restricted_content(msg: &teloxide::types::Message) -> bool {
    if let Some(entities) = msg.parse_entities()
        && entities
            .iter()
            .any(|entity| msg_entity_is_restricted_content(entity.kind()))
    {
        return true;
    }
    if let Some(entities) = msg.parse_caption_entities()
        && entities
            .iter()
            .any(|entity| msg_entity_is_restricted_content(entity.kind()))
    {
        return true;
    }
    false
}

async fn handle_public_msg(
    tg_bot: &teloxide::Bot,
    xpub: &Xpub,
    electrs_rest_api_url: &str,
    msg_sender: &teloxide::types::User,
    msg: &teloxide::types::Message,
) -> anyhow::Result<()> {
    if !msg_contains_restricted_content(msg)
        || user_is_approved(xpub, electrs_rest_api_url, msg_sender.id).await?
    {
        tracing::debug!(
            %msg.id,
            username=msg_sender.username,
            first_name=msg_sender.first_name,
            last_name=msg_sender.last_name,
            "Approved message"
        );
        return Ok(());
    }
    tracing::debug!(
        %msg.id,
        username=msg_sender.username,
        first_name=msg_sender.first_name,
        last_name=msg_sender.last_name,
        "Deleting message"
    );
    match tg_bot.delete_message(msg.chat.id, msg.id).send().await {
        Ok(teloxide::types::True)
        | Err(teloxide::RequestError::Api(
            teloxide::ApiError::MessageToDeleteNotFound,
        )) => {}
        Err(err) => return Err(err.into()),
    }
    tracing::info!(
        %msg.id,
        username=msg_sender.username,
        first_name=msg_sender.first_name,
        last_name=msg_sender.last_name,
        "Deleted message"
    );
    let signet_addr = generate_signet_addr(xpub, msg_sender.id)?;
    let msg_intro = match &msg_sender.username {
        Some(username) => {
            format!("@{}, your", teloxide::utils::markdown::escape(username))
        }
        None => "Your".to_owned(),
    };
    let reply_text = format!(
        "{msg_intro} message in DC\\-Insiders has been deleted\\. \
         You are restricted from posting mentions, links, attachments, and \
         media\\. You can remove this restriction by sending 1 Signet coin to \
         `{}`, and sending a message in this DM chat\\.",
        signet_addr,
    );
    let _msg: teloxide::types::Message = tg_bot
        .send_message(ChatId::from(msg_sender.id), reply_text)
        .with_payload_mut(|send_message| {
            send_message.parse_mode =
                Some(teloxide::types::ParseMode::MarkdownV2)
        })
        .send()
        .await?;
    tracing::trace!(
        user_id=%msg_sender.id,
        username=msg_sender.username,
        first_name=%msg_sender.first_name,
        last_name=msg_sender.last_name,
        %signet_addr,
        "notification message sent successfully",
    );
    Ok(())
}

async fn handle_msg(
    tg_bot: &teloxide::Bot,
    xpub: &Xpub,
    electrs_rest_api_url: &str,
    msg: &teloxide::types::Message,
) -> anyhow::Result<()> {
    let msg_sender = msg.from.as_ref().ok_or_else(|| {
        anyhow::anyhow!("expected message {} to have a sender", msg.id)
    })?;
    if msg.chat.is_private() {
        handle_dm(tg_bot, xpub, electrs_rest_api_url, msg_sender).await
    } else {
        handle_public_msg(tg_bot, xpub, electrs_rest_api_url, msg_sender, msg)
            .await
    }
}

async fn handle_update(
    tg_bot: &teloxide::Bot,
    xpub: &Xpub,
    electrs_rest_api_url: &str,
    update: &teloxide::types::Update,
) -> anyhow::Result<()> {
    tracing::debug!(?update);
    match &update.kind {
        teloxide::types::UpdateKind::ChatJoinRequest(join_request) => {
            let user = &join_request.from;
            tracing::info!(
                user_id=%user.id,
                username=user.username,
                first_name=%user.first_name,
                last_name=user.last_name,
                "Handling chat join request",
            );
            handle_chat_join_request(tg_bot, xpub, join_request).await
        }
        teloxide::types::UpdateKind::EditedMessage(msg) => {
            let user = msg.from.as_ref();
            tracing::debug!(
                %msg.id,
                username=user.and_then(|user| user.username.as_ref()),
                first_name=user.map(|user| user.first_name.as_str()),
                last_name=user.and_then(|user| user.last_name.as_ref()),
                "Handling edited message",
            );
            handle_msg(tg_bot, xpub, electrs_rest_api_url, msg).await
        }
        teloxide::types::UpdateKind::Message(msg) => {
            let user = msg.from.as_ref();
            tracing::debug!(
                %msg.id,
                username=user.and_then(|user| user.username.as_ref()),
                first_name=user.map(|user| user.first_name.as_str()),
                last_name=user.and_then(|user| user.last_name.as_ref()),
                "Handling message",
            );
            handle_msg(tg_bot, xpub, electrs_rest_api_url, msg).await
        }
        _ => Err(anyhow::anyhow!(
            "Unexpected update kind: `{:?}`",
            update.kind
        )),
    }
}

/// Returns highest update sequence ID.
async fn handle_updates_inner(
    tg_bot: &teloxide::Bot,
    next_update_seq_id: Option<i32>,
    xpub: &Xpub,
    electrs_rest_api_url: &str,
) -> anyhow::Result<Option<UpdateSeqId>> {
    use teloxide::types::AllowedUpdate;
    const LONG_POLLING_TIMEOUT_S: u32 = 15;
    let req = tg_bot.get_updates().with_payload_mut(|get_updates| {
        get_updates.offset = next_update_seq_id;
        get_updates.timeout = Some(LONG_POLLING_TIMEOUT_S);
        get_updates.allowed_updates = Some(vec![
            AllowedUpdate::ChatJoinRequest,
            AllowedUpdate::EditedMessage,
            AllowedUpdate::Message,
        ]);
    });
    let updates = req.send().await?;
    tracing::trace!("received {} update(s)", updates.len());
    let res = updates.last().map(|last_update| last_update.id);
    for update in updates {
        let () =
            handle_update(tg_bot, xpub, electrs_rest_api_url, &update).await?;
    }
    Ok(res)
}

async fn handle_updates(
    tg_bot: teloxide::Bot,
    xpub: Xpub,
    electrs_rest_api_url: String,
) -> anyhow::Error {
    tracing::debug!("subscribing to updates via long polling...");
    let mut next_update_seq_id = None;
    loop {
        match handle_updates_inner(
            &tg_bot,
            next_update_seq_id,
            &xpub,
            electrs_rest_api_url.as_str(),
        )
        .await
        {
            Ok(None) => {}
            Ok(Some(highest_update_seq_id)) => {
                next_update_seq_id = Some(highest_update_seq_id.as_offset());
            }
            Err(err) => return err,
        };
    }
}

// Adds the key to the error if not found
fn get_var<K>(key: K) -> anyhow::Result<String>
where
    K: AsRef<std::ffi::OsStr>,
{
    let key = key.as_ref();
    std::env::var(key).map_err(|err| match err {
        std::env::VarError::NotPresent => anyhow::anyhow!(
            "environment variable `{}` not found",
            key.display()
        ),
        err => err.into(),
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let () = dotenvy::from_path(".env")?;
    let () = set_tracing_subscriber()?;
    let tg_bot = teloxide::Bot::from_env();
    let xpub = {
        let xpub_str = get_var("SIGNET_XPUB")?;
        Xpub::from_str(&xpub_str)?
    };
    let electrs_rest_api_url = get_var("ELECTRS_REST_API_URL")?;
    match futures::future::select(
        tokio::signal::ctrl_c().boxed(),
        handle_updates(tg_bot, xpub, electrs_rest_api_url).boxed(),
    )
    .await
    {
        Either::Left((ctrl_c_signal, _handle_updates)) => {
            ctrl_c_signal.map_err(anyhow::Error::from)
        }
        Either::Right((err, _handle_ctrl_c)) => Err(err),
    }
}
