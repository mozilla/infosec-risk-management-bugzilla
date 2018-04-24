# Setup

- Bugzilla credentials are passed as environment variable `BUGZILLA_API_KEY`
- CASA credentials are passed as environment variable `CASA_API_KEY`


For Bugzilla, you need a "personal token" that you can generate in your user profile.

For CASA, you need a "personal OAuth token" that you can generate at https://biztera.com/developer/tokens for a user that has
"security moderator" privileges (generally you want this to be a dedicated user).

Scopes required:
- `write_project` (to change the security tab values)
- `read_project` (to check the security tab values, so that we know if it needs to be changed)
- `read_friend` (to lookup the user in Biztera and notify that a change has been posted on their behalf)

## Usage

See `config.yaml` for configuration and `./asssigner.py --help` for available commands.

# Features

## Bugzilla auto-assignment

This is a simple script using `simple_bugzilla` in order to assign VA, RRA bugs automatically.
It aims to be as simple as possible.

## Casa-Bugzilla sync

This is another simple script which scans recent Bugzilla changes for VA, RRA components, and updates CASA automatically
if a bug has been closed, with the correct status. This updates CASA's security tab, and uses a special account that has
"security moderator" privileges.

Note that CASA is short for Contracts and Spends Approval, and runs on biztera.com
