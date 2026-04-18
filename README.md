# Windrose

Consolidated research engine combining:
- **Auth**: Argon2id, API keys, sessions, multi-org support
- **Search**: Web search with researcher agent + widgets
- **Chat**: Streaming chat with history

## Auth Flow

```
Request → x-session-token header
       → lib/auth/middleware.ts
       → verifySession() → getUserOrganizations()
       → Route handler with { userId, org, permissions }
```

## Multi-Org Support

```
User ←→ user_organizations ←→ Organization
                              ↓
                        organization_permissions
                              ↓
                        Role → Permissions
```

## API Endpoints

| Endpoint | Purpose |
|----------|--------|
| `POST /api/auth/login` | Password OR API key auth |
| `POST /api/chat` | Streaming chat with search |
| `POST /api/search` | Web search |
| `POST /api/uploads` | File uploads |

## Permissions

| Permission | Description |
|-----------|-------------|
| `org:manage` | Manage organization |
| `org:invite` | Invite members |
| `chat:create` | Create chats |
| `chat:share` | Share chats |
| `chat:delete` | Delete chats |

## Development

```bash
npm install
npm run dev
npm test
```
