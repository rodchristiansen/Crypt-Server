# Crypt-Server

**[Crypt][1]** is a tool for securely storing secrets such as FileVault 2 recovery keys. It is made up of a client app, and a Django web app for storing the keys.

This Docker image contains the fully configured Crypt Django web app. A default admin user has been preconfigured, use admin/password to login.
If you intend on using the server for anything semi-serious it is a good idea to change the password or add a new admin user and delete the default one.

## Features

- Secrets are encrypted in the database
- All access is audited - all reasons for retrieval and approval are logged along side the users performing the actions
- Two step approval for retrieval of secrets is enabled by default
- Approval permission can be given to all users (so just any two users need to approve the retrieval) or a specific group of users

  [1]: https://github.com/grahamgilbert/Crypt

## Migration helper

The new migration helper can generate an encryption key for the Go backend:

```
go run ./cmd/cryptctl gen-key
```

Convert a Django JSON fixture (from `manage.py dumpdata`) into an encrypted export file:

```
go run ./cmd/cryptctl import-fixture \
  --input legacy.json \
  --output migration-export.json \
  --legacy-key-file legacy-field-encryption-key.txt \
  --new-key-file new-field-encryption-key.txt \
  --password-map password-map.csv
```

Optional password map CSV format:

```
username_or_email,password,must_reset_password
admin@example.com,Str0ng!Passw0rd,false
```

## Installation instructions

It is recommended that you use [Docker](https://github.com/grahamgilbert/Crypt-Server/blob/master/docs/Docker.md) to run this, but if you wish to run directly on a host, installation instructions are over in the [docs directory](https://github.com/grahamgilbert/Crypt-Server/blob/master/docs/Installation_on_Ubuntu_1404.md)

### Migrating from versions earlier than Crypt 3.0

Crypt 3 changed it's encryption backend, so when migrating from versions earlier than Crypt 3.0, you should first run Crypt 3.2.0 to perform the migration, and then upgrade to the latest version. The last version to support legacy migrations was Crypt 3.2.

## Settings

All settings that would be entered into `settings.py` can also be passed into the Docker container as environment variables.

- `FIELD_ENCRYPTION_KEY` - The key to use when encrypting the secrets. This is required.

- `SESSION_KEY` - A random string (at least 32 bytes) used to sign session cookies. This is required.

- `DATABASE_URL` - Postgres connection string. Mutually exclusive with `SQLITE_PATH`.

- `SQLITE_PATH` - SQLite database file path. Must be a file path. Mutually exclusive with `DATABASE_URL`.

- `SESSION_COOKIE_SECURE` - Set to `true` to mark session cookies as secure (recommended when using HTTPS).

- `SAML_CONFIG_FILE` - Path to a YAML file containing SAML configuration. See `docs/saml-config.sample.yaml` for all supported fields.

- `SEND_EMAIL` - Crypt Server can send email notifcations when secrets are requested and approved. Set `SEND_EMAIL` to True, and set `HOST_NAME` to your server's host and URL scheme (e.g. `https://crypt.example.com`). For configuring your email settings, see the [Django documentation](https://docs.djangoproject.com/en/3.1/ref/settings/#std:setting-EMAIL_HOST).

- `EMAIL_SENDER` - The email address to send emaiil notifications from when secrets are requests and approved. Ensure this is verified if you are using SES. Does nothing unless `SEND_EMAIIL` is True.

- `APPROVE_OWN` - By default, users with approval permissons can approve their own key requests. By setting this to False in settings.py (or by using the `APPROVE_OWN` environment variable with Docker), users cannot approve their own requests.

- `ALL_APPROVE` - By default, users need to be explicitly given approval permissions to approve key retrieval requests. By setting this to True in `settings.py`, all users are given this permission when they log in.

- `ROTATE_VIEWED_SECRETS` - With a compatible client (such as Crypt 3.2.0 and greater), Crypt Server can instruct the client to rotate the secret and re-escrow it when the secret has been viewed. Enable by setting this to `True` or by using `ROTATE_VIEWED_SECRETS` and setting to `true`.

- `HOST_NAME` - Set the host name of your instance - required if you do not have control over the load balancer or proxy in front of your Crypt server (see [the Django documentation](https://docs.djangoproject.com/en/4.1/ref/settings/#csrf-trusted-origins)).

- `CSRF_TRUSTED_ORIGINS` - Is a list of trusted origins expected to make requests to your Crypt instance, normally this is the hostname

## Database migrations

The Go server applies embedded SQL migrations on startup and records applied versions in `schema_migrations`.

Migration file naming: `NNN_description.sql` (for example, `002_add_requests.sql`).

Flags:

- `-validate-migrations` - Validate embedded migrations and exit.
- `-print-migrations` - Print embedded migrations and exit.
- `-migrations-driver` - Limit the validation/print target to `postgres` or `sqlite` (default: both).

Example:

```
./crypt-server -validate-migrations -migrations-driver=postgres
```
## Screenshots

Main Page:
![Crypt Main Page](https://raw.github.com/grahamgilbert/Crypt-Server/master/docs/images/home.png)

Computer Info:
![Computer info](https://raw.github.com/grahamgilbert/Crypt-Server/master/docs/images/admin_computer_info.png)

User Key Request:
![Userkey request](https://raw.github.com/grahamgilbert/Crypt-Server/master/docs/images/user_key_request.png)

Manage Requests:
![Manage Requests](https://raw.github.com/grahamgilbert/Crypt-Server/master/docs/images/manage_requests.png)

Approve Request:
![Approve Request](https://raw.github.com/grahamgilbert/Crypt-Server/master/docs/images/approve_request.png)

Key Retrieval:
![Key Retrieval](https://raw.github.com/grahamgilbert/Crypt-Server/master/docs/images/key_retrieval.png)
