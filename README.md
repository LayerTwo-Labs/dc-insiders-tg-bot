# DC Insiders Telegram Bot

This bot guards the DC Insiders Telegram group.

## Configuration

The `TELOXIDE_TOKEN` env var is the telegram bot token. It is required, and
can also be set in a `.env` file in the working directory.

The `ELECTRS_REST_API_URL` env var is the URL for an electrs REST API server for L2L signet. It is required, and can also be set in a `.env` file in the working directory.

The `SIGNET_XPUB` env var is a Base58ck encoded BIP32 XPub, used to derive unique addresses to receive from each Telegram user. It is required, and can also be set in a `.env` file in the working directory.

The `RUST_LOG` env var, which can also be set in a `.env` file in the working directory, controls logging verbosity.
