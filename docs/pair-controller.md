# pair-controller.sh (v4)

This tool pairs SSH access to controllers and manages convenient SSH host aliases.

## Concepts

- **Controller alias (ALIAS)**: a human name for a controller role/device  
  Examples: `GWA`, `GWB`, `Lift`

- **Project id (PROJECT)**: the project identifier  
  Example: `102156`

- **Stable SSH host alias**:  
  `ALIAS-PROJECT[-CONTROLLER_ID]`  
  Examples:
  - `GWA-102156`
  - `GWB-102156`
  - `Lift-102156`
  - `GWA-102156-spare` (only if you use `--controller spare`)

- **Current project**: when set, bare aliases resolve within that project:
  - `ssh GWA` connects to `GWA-<current_project>`
  - `ssh GWB` connects to `GWB-<current_project>`
  - `ssh Lift` connects to `Lift-<current_project>`

## Install prerequisites

- `ssh`, `ssh-copy-id` (optional but recommended)
- `jq` (required)
- A local SSH keypair (recommended: ed25519)

Generate a key if needed:

```bash
ssh-keygen -t ed25519
```

## Pair controllers into a project

Register each controller with its ALIAS and IP/host:

```bash
./pair-controller.sh --project 102156 --alias GWA 10.1.2.1 root
./pair-controller.sh --project 102156 --alias GWB 10.2.1.3 root
./pair-controller.sh --project 102156 --alias Lift 10.5.6.3 root
```

This creates SSH hosts:

- `GWA-102156`
- `GWB-102156`
- `Lift-102156`

Connect:

```bash
ssh GWA-102156
```

## Set current project (drop the suffix)

```bash
./pair-controller.sh --set-current-project 102156
```

Now you can:

```bash
ssh GWA
ssh GWB
ssh Lift
```

Under the hood, the script writes a managed block into `~/.ssh/config`:

- `Host GWA` points to the IP/user/key for `GWA-102156`
- `Host GWB` points to `GWB-102156`
- `Host Lift` points to `Lift-102156`

When you change the current project, that block is rewritten.

## Temporarily jump to another project

Even if your current project is `102156`, you can connect to another project's controller without switching:

```bash
ssh GWA-204400
```

## List, info, delete

List everything:

```bash
./pair-controller.sh --list
```

Show details:

```bash
./pair-controller.sh --info GWA-102156
```

Delete a registration:

```bash
./pair-controller.sh --delete GWA-102156
```

## Repair / re-pair

If keys or SSH config got out of sync, re-pair a host alias:

```bash
./pair-controller.sh --repair GWA-102156
```

This forces key installation and rewrites the matching `Host GWA-102156` block.

## Strict vs permissive host key checking

Default is permissive:

- `StrictHostKeyChecking no`
- Per-host `UserKnownHostsFile` to avoid cross-project collisions when IPs are reused.

Enable stricter behavior:

```bash
./pair-controller.sh --strict --project 102156 --alias GWA 10.1.2.1 root
```

This uses:

- `StrictHostKeyChecking accept-new`

## Notes on duplicates

If you ever need multiple controllers with the same ALIAS in a project, use `--controller` to create distinct stable hosts:

```bash
./pair-controller.sh --project 102156 --alias GWA --controller spare 10.1.2.99 root
```

Stable host becomes:

- `GWA-102156-spare`

Bare alias resolution (`ssh GWA`) will choose the first `GWA*` entry it finds for that project. In practice you said duplicates won't be relevant; if you do hit this, use the stable alias (`ssh GWA-102156-spare`) and/or adjust registrations.

## Compatibility

Older versions used `--unique-id` and `--set-current`. v4 keeps them as deprecated shims:

- `--unique-id` is treated as `--project`
- `--set-current <HOSTALIAS>` sets current project to that host's project