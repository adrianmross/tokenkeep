# tokenkeep

Keeps a CLI's login token in the OS keyring. One Go package, no dependencies.

| OS | Backend | Tool it runs |
| --- | --- | --- |
| macOS | `macos-keychain` | `security` |
| Linux | `secret-service` | `secret-tool` |

```go
k := tokenkeep.Keyring{Service: "mycli"}
backend := tokenkeep.Backend() // "" when this machine has no keyring

err := k.Write(backend, "https://api.example.com", token)
tok, err := k.Read(backend, "https://api.example.com") // tokenkeep.ErrNotFound when logged out
err = k.Delete(backend, "https://api.example.com")
```

Save the backend name beside the account and pass it back to `Read`. A machine that has lost the tool then reports an error instead of looking logged out.

## What it guarantees

- The token is passed to the tool on stdin, never as an argument, so it does not show in `ps`.
- A macOS write is read back, because `security -i` exits 0 even when it fails.
- `ErrNotFound` means the item is missing. A locked keychain or denied access is a different error.

## What it does not

- On macOS, an item written by `security` can be read by any process running as the same user.
- There is no Windows backend and no file fallback. When `Backend()` returns `""`, store the token yourself, for example in a `0600` file.

## Tests

`go test ./...` does not touch your keyring. To run the round trip against the real one:

```sh
TOKENKEEP_LIVE=1 go test ./...
```
