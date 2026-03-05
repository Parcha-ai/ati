# Google Workspace CLI (gws) via ATI

Use `ati run google_workspace -- <args>` to access all 25 Google Workspace APIs. ATI handles credential injection — you never touch auth directly.

## CLI Structure

```
ati run google_workspace -- <service> <resource> <method> [flags]
```

Output is JSON by default. Add `--format json` to any subcommand for structured output.

## Common Services

| Service | Description | Example Resource |
|---------|-------------|-----------------|
| `drive` | Google Drive | `files`, `permissions`, `comments` |
| `gmail` | Gmail | `messages`, `labels`, `drafts`, `threads` |
| `calendar` | Google Calendar | `events`, `calendarList` |
| `sheets` | Google Sheets | `spreadsheets`, `values` |
| `docs` | Google Docs | `documents` |
| `chat` | Google Chat | `spaces`, `messages` |
| `admin` | Workspace Admin | `users`, `groups`, `orgunits` |
| `tasks` | Google Tasks | `tasklists`, `tasks` |
| `slides` | Google Slides | `presentations` |
| `forms` | Google Forms | `forms`, `responses` |
| `meet` | Google Meet | `conferenceRecords`, `spaces` |
| `vault` | Google Vault | `matters`, `holds`, `exports` |
| `people` | People API | `people`, `contactGroups` |
| `groups` | Cloud Identity Groups | `groups`, `memberships` |

## Key Examples

### Drive — List files
```bash
ati run google_workspace -- drive files list --pageSize 10
```

### Drive — Search files
```bash
ati run google_workspace -- drive files list --q "name contains 'report' and mimeType='application/pdf'"
```

### Drive — Download a file
```bash
ati run google_workspace -- drive files export --fileId FILE_ID --mimeType "text/plain"
```

### Gmail — List messages
```bash
ati run google_workspace -- gmail messages list --userId me --maxResults 10
```

### Gmail — Search messages
```bash
ati run google_workspace -- gmail messages list --userId me --q "from:boss@company.com is:unread"
```

### Gmail — Send email
```bash
ati run google_workspace -- gmail messages send --userId me \
  --to "recipient@example.com" --subject "Update" --body "Here's the latest."
```

### Calendar — List upcoming events
```bash
ati run google_workspace -- calendar events list --calendarId primary \
  --timeMin "2026-03-01T00:00:00Z" --maxResults 20 --orderBy startTime --singleEvents true
```

### Calendar — Create event
```bash
ati run google_workspace -- calendar events insert --calendarId primary \
  --summary "Team Sync" --start.dateTime "2026-03-10T10:00:00-05:00" \
  --end.dateTime "2026-03-10T11:00:00-05:00"
```

### Sheets — Read a range
```bash
ati run google_workspace -- sheets spreadsheets.values get \
  --spreadsheetId SHEET_ID --range "Sheet1!A1:D10"
```

### Sheets — Write values
```bash
ati run google_workspace -- sheets spreadsheets.values update \
  --spreadsheetId SHEET_ID --range "Sheet1!A1" \
  --valueInputOption RAW --values '[["Name","Score"],["Alice",95]]'
```

### Admin — List users
```bash
ati run google_workspace -- admin users list --domain example.com --maxResults 50
```

### Chat — Send message to a space
```bash
ati run google_workspace -- chat spaces.messages create \
  --parent "spaces/SPACE_ID" --text "Hello from ATI!"
```

## Discovering Commands

Use `--help` on any command to see available subcommands and flags:

```bash
ati run google_workspace -- --help
ati run google_workspace -- drive --help
ati run google_workspace -- drive files --help
ati run google_workspace -- drive files list --help
```

## Pagination

For paginated results, use `--page-all` to fetch all pages automatically:

```bash
ati run google_workspace -- drive files list --page-all
```

Or handle pagination manually with `--pageToken`:

```bash
ati run google_workspace -- drive files list --pageSize 100 --pageToken NEXT_TOKEN
```

## Authentication

### Interactive (machine with a browser)

```bash
ati run google_workspace -- auth setup
```

This creates a Cloud project, enables APIs, and stores encrypted credentials at `~/.config/gws/`.

### Headless / Service Account (recommended for agents)

Store the service account JSON in ATI's keyring. ATI materializes it as a temp file (0600, wiped on exit) and sets `GOOGLE_WORKSPACE_CLI_CREDENTIALS_FILE` — the agent never sees raw credentials.

```bash
ati key set google_workspace_credentials "$(cat service-account.json)"
```

### Proxy Mode with Impersonation

Service accounts create files in their own invisible Drive. To have files appear in a real user's Drive, enable [domain-wide delegation](https://developers.google.com/identity/protocols/oauth2/service-account#delegatingauthority) on the service account and uncomment `GOOGLE_WORKSPACE_CLI_IMPERSONATED_USER` in the manifest.

On the proxy server:
```bash
ati key set google_workspace_credentials "$(cat service-account.json)"
ati key set google_workspace_user analyst@company.com
```

The sandboxed agent just calls `ati run` — zero credentials, zero config. Files are created in the impersonated user's Drive, visible to them immediately.

### Check auth status

```bash
ati run google_workspace -- auth status
```

## Tips

- gws defaults to JSON output — add `--format json` explicitly if needed, or `--format table` for readable output
- Use `--fields` to select specific fields and reduce response size
- For batch operations, loop over results from a list command
- Gmail `--userId me` refers to the authenticated user
- Calendar `--calendarId primary` refers to the user's primary calendar
- Drive file IDs are in the `id` field of list responses
