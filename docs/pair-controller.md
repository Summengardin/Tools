# Quick Reference: Common Scenarios

## Recommended Workflow: Use Current Project Feature

**Best practice for multiple sites with the same IP:**

```bash
# ONE-TIME SETUP: Pair all your sites
./pair-controller.sh --unique-id site-a 192.168.1.50 root
./pair-controller.sh --unique-id site-b 192.168.1.50 root
./pair-controller.sh --unique-id site-c 192.168.1.50 root

# Set which one is active
./pair-controller.sh --set-current site-a-50

# Now you can ALWAYS use the same command:
ssh GWB  # Connects to Site A

# When you move to Site B, just switch:
./pair-controller.sh --set-current site-b-50
ssh GWB  # Now connects to Site B

# Check which is active anytime:
./pair-controller.sh --show-current

# List all and see which is current (marked with ★):
./pair-controller.sh --list
```

**Benefits:**
- ✅ Always use `ssh GWB` - muscle memory!
- ✅ No re-pairing needed when switching sites
- ✅ All controllers stay registered
- ✅ Quick one-command switching
- ✅ Can still use specific aliases: `ssh site-a-50`, `ssh site-b-50`

---

## Scenario 1: Multiple Controllers, Same IP, Different Projects

**Problem**: You work on different projects with GWB controllers that all use 192.168.1.50

**Solution**: Use unique-id to distinguish them

```bash
# Project Alpha
./pair-controller.sh --unique-id alpha 192.168.1.50 root
# Connect: ssh alpha-50

# Project Beta  
./pair-controller.sh --unique-id beta 192.168.1.50 root
# Connect: ssh beta-50

# Project Gamma
./pair-controller.sh --unique-id gamma 192.168.1.50 root
# Connect: ssh gamma-50
```

## Scenario 2: Your SSH Key Was Removed

**Problem**: Controller admin reset the system or removed your key

**Solution**: Use repair to quickly re-pair

```bash
# List your controllers to find the alias
./pair-controller.sh --list

# Re-pair without re-entering all parameters
./pair-controller.sh --repair alpha-50

# Or if you lost the alias name, check info first
./pair-controller.sh --info alpha-50
./pair-controller.sh --repair alpha-50
```

## Scenario 3: Same Controller, Different Locations

**Problem**: You move a GWB controller between buildings (same physical device, different networks)

**Solution**: Use unique-id based on location, not the device

```bash
# Controller in Building A
./pair-controller.sh --unique-id bldg-a 192.168.1.50 root
# Connect: ssh bldg-a-50

# Later, same controller moved to Building B
./pair-controller.sh --unique-id bldg-b 192.168.1.50 root
# Connect: ssh bldg-b-50

# You now have both in history
./pair-controller.sh --list
```

## Scenario 4: Switching Your SSH Key

**Problem**: You generated a new SSH key and want to update the controller

**Solution**: Re-pair with new key path

```bash
# Generate new key
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_new

# Re-pair with explicit new key
./pair-controller.sh 192.168.1.50 root alpha-50 ~/.ssh/id_ed25519_new.pub

# Or use repair if it's already your default key
./pair-controller.sh --repair alpha-50
```

## Scenario 5: Quick Status Check

**Problem**: Not sure which controllers you have registered or if they're reachable

**Solution**: Use list and info commands

```bash
# See all registered controllers
./pair-controller.sh --list

# Check if specific controller is reachable
./pair-controller.sh --info alpha-50
# Output shows connection test result

# Try connecting
ssh alpha-50
```

## Scenario 6: Clean Up Old Controllers

**Problem**: You finished a project and want to remove the controller entry

**Solution**: Use delete command

```bash
# Remove controller registration
./pair-controller.sh --delete alpha-50

# This removes:
# - Metadata file
# - Known hosts file  
# - SSH config entry
```

## Common Commands Cheat Sheet

```bash
# Pair new controller
./pair-controller.sh <IP> <user>

# Pair with unique ID
./pair-controller.sh --unique-id <id> <IP> <user>

# Pair with custom alias
./pair-controller.sh <IP> <user> <alias>

# Pair with specific key
./pair-controller.sh <IP> <user> <alias> <pubkey_path>

# Re-pair existing controller
./pair-controller.sh --repair <alias>

# Set as current (creates GWB alias)
./pair-controller.sh --set-current <alias>

# Show current active controller
./pair-controller.sh --show-current

# List all controllers
./pair-controller.sh --list

# Get controller info
./pair-controller.sh --info <alias>

# Delete controller
./pair-controller.sh --delete <alias>

# Verbose output (for debugging)
./pair-controller.sh -v <IP> <user>

# Dry run (see what would happen)
./pair-controller.sh -n <IP> <user>
```

## Workflow Example: Typical Day

```bash
# Monday: Start new project "Phoenix" - ONE TIME SETUP
./pair-controller.sh --unique-id phoenix 192.168.1.50 root
./pair-controller.sh --set-current phoenix-50
ssh GWB  # Test connection

# Tuesday: Someone reset the controller
./pair-controller.sh --repair phoenix-50  # Quick fix!
ssh GWB  # Back in business

# Wednesday: Switch to project "Orion" (same IP, different controller)
./pair-controller.sh --unique-id orion 192.168.1.50 root  # ONE TIME
./pair-controller.sh --set-current orion-50  # Switch to it
ssh GWB  # Different controller, same command!

# Thursday: Need to check Phoenix again
./pair-controller.sh --set-current phoenix-50  # Just switch back
ssh GWB  # Now on Phoenix again

# Friday: Check what you have
./pair-controller.sh --list  # Shows both, ★ marks current
./pair-controller.sh --show-current  # Shows Phoenix is active

# Project Phoenix complete - clean up
./pair-controller.sh --delete phoenix-50
```

## Troubleshooting

### "Cannot reach IP:22"
- Check network connectivity
- Verify controller is powered on
- Confirm IP address is correct
- Try: `ping 192.168.1.50`

### "Public key not found"
- Generate new key: `ssh-keygen -t ed25519`
- Or specify key: `./pair-controller.sh <IP> <user> <alias> ~/.ssh/your_key.pub`

### "Password authentication failed"
- Install sshpass: `sudo apt install sshpass`
- Use: `SSH_PASSWORD='yourpass' ./pair-controller.sh <IP> <user>`
- Or enter password when prompted

### "Controller already registered"
- View info: `./pair-controller.sh --info <alias>`
- Delete and re-pair: `./pair-controller.sh --delete <alias>`
- Or force overwrite by confirming when prompted