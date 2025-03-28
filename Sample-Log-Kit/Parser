# Parser Name: ThinkinfosecAttackSimParser
# Description: Parses JSON logs from the Python Attack Simulator (sourcetype=cs:test:attacksim:chain)
#              and maps fields to CrowdStrike Common Schema (CPS).

# Match events with the specific sourcetype tag/field
@sourcetype := "cs:test:attacksim:chain"

# --- Handle different HEC input formats ---
# The script sends data differently depending on the target HEC URL.
# Check if 'attributes' field exists (sent to /api/v1/humio-structured)
# Otherwise, assume 'event' field exists (sent to /services/collector/event)
case {
  attributes != null | attributes? := attributes; # Assign 'attributes' content to 'attributes?' variable
  event != null      | attributes? := event;      # Assign 'event' content to 'attributes?' variable
  *                  | attributes? := ""; drop()  # If neither exists, assign empty and drop the event
}

# Parse the main JSON payload (which is now in the 'attributes?' variable)
| parseJson(attributes?)

# --- Core Field Mapping (using coalesce to handle potential missing fields) ---
# Use coalesce(extractedField, @existingField) to prefer the newly parsed field
# but keep the existing one (like @timestamp) if parsing fails or field is missing.

# Timestamp
@timestamp := coalesce(timestamp, @timestamp)

# Event details
event.category   := category ?? event.category   # Use existing LogScale field if parser extracts 'category'
event.type       := type ?? event.type
event.outcome    := outcome ?? event.outcome
event.action     := action ?? event.action
event.provider   := provider ?? event.provider
event.kind       := kind ?? event.kind
event.created    := created ?? event.created
event.module     := module ?? event.module
event.timezone   := timezone ?? event.timezone
log.level        := log.level ?? loglevel # Map log.level if present

# Host details
host.name        := coalesce(host.name, name, host) # Try 'host.name', then 'name', then original 'host' field
host.hostname    := hostname ?? host.hostname
host.ip          := ip ?? host.ip             # Map 'ip' array/string from host object
host.mac         := mac ?? host.mac           # Map 'mac' array/string from host object
host.os.name     := os.name ?? host.os.name
host.os.family   := os.family ?? host.os.family # Will set 'event_platform' derived field in Falcon
host.os.version  := os.version ?? host.os.version
host.id          := host.id ?? host_guid      # Map host.id if present

# User details
user.name        := coalesce(user.name, username) # Map user.name or username
user.domain      := domain ?? user.domain
user.id          := coalesce(user.id, uid)    # Map user.id or uid (from Linux process)
user.group.id    := coalesce(user.group.id, gid) # Map user.group.id or gid (from Linux process)

# Process details
process.pid                 := pid ?? process.pid
process.name                := process.name ?? proc_name # Map process.name or proc_name
process.executable          := executable ?? process.executable
process.executable_name     := executable_name ?? process.executable_name # Map pre-calculated basename
process.command_line        := command_line ?? process.command_line
process.parent.pid          := parent.pid ?? parent_pid ?? process.parent.pid
process.parent.name         := parent.name ?? parent_proc_name ?? process.parent.name
process.parent.executable   := parent.executable ?? process.parent.executable
process.parent.executable_name := parent.executable_name ?? process.parent.executable_name # Map pre-calculated basename
process.entity_id           := entity_id ?? process.entity_id
process.parent.entity_id    := parent.entity_id ?? process.parent.entity_id
# Linux specific process fields
process.uid                 := uid ?? process.uid
process.gid                 := gid ?? process.gid
# Hashes
process.hash.md5            := hash.md5 ?? process.hash.md5
process.hash.sha1           := hash.sha1 ?? process.hash.sha1
process.hash.sha256         := hash.sha256 ?? process.hash.sha256

# Network details (map source/destination)
source.ip        := source.ip ?? src_ip ?? LocalIP ?? LocalAddressIP4 # Map various possibilities for source IP
source.port      := source.port ?? src_port ?? LocalPort ?? LPort
source.bytes     := source.bytes ?? bytes_out
destination.ip   := destination.ip ?? dest_ip ?? RemoteIP ?? RemoteAddressIP4 # Map various possibilities for dest IP
destination.port := destination.port ?? dest_port ?? RPort
destination.bytes:= destination.bytes ?? bytes_in
destination.domain:= destination.domain ?? dest_domain
network.transport     := network.transport ?? transport
network.protocol      := network.protocol ?? protocol_name # Field like 'http', 'smb'
network.iana_number   := network.iana_number ?? protocol ?? iana_number # Field like 6, 17
network.direction     := network.direction ?? direction
network.community_id  := network.community_id ?? community_id
network.bytes         := network.bytes ?? total_bytes

# URL details
url.original    := url.original ?? original_url
url.path        := url.path ?? path
url.domain      := url.domain ?? http_domain
url.query       := url.query ?? query

# HTTP details
http.request.method  := http.request.method ?? request_method
http.response.status_code := http.response.status_code ?? status_code

# File details
file.path        := file.path ?? filepath
file.name        := file.name ?? filename
file.directory   := file.directory ?? directory
file.extension   := file.extension ?? extension
file.size        := file.size ?? filesize
# Hashes (can also be on file object)
file.hash.md5    := file.hash.md5 ?? file_md5
file.hash.sha1   := file.hash.sha1 ?? file_sha1
file.hash.sha256 := file.hash.sha256 ?? file_sha256

# Registry details
registry.path    := registry.path ?? reg_path
registry.hive    := registry.hive ?? hive
registry.key     := registry.key ?? reg_key
registry.value   := registry.value ?? reg_value
# registry.data.strings is tricky to map directly, often seen in raw log

# Map Observer/Agent if present
observer.vendor    := observer.vendor ?? obs_vendor
observer.product   := observer.product ?? obs_product
observer.type      := observer.type ?? obs_type
observer.hostname  := observer.hostname ?? obs_hostname
agent.type         := agent.type ?? agent_type
agent.version      := agent.version ?? agent_version

# Add generated ATT&CK tags
# This assumes the 'tags' field in the JSON is an array of strings
| arrayextend(field=@tags, array=tags) # Add tags from the event to the LogScale @tags field

# --- Field Aliasing/Copying for Native Falcon Fields ---
# Try to populate fields similar to the blue text if the primary CPS mapping didn't cover them
LocalIP      := source.ip ?? LocalIP   # Ensure LocalIP exists if source.ip was mapped
LocalPort    := source.port ?? LocalPort
RemoteIP     := destination.ip ?? RemoteIP
RemotePort   := destination.port ?? RemotePort
Protocol     := network.iana_number ?? Protocol # Ensure Protocol (numeric) exists
ImageFileName := process.executable ?? ImageFileName # Often expects full path

# Attempt to extract ContextBaseFileName if not provided directly
# This is heuristic and might not always match Falcon's internal logic
ContextBaseFileName := process.executable_name ?? basename(process.executable) ?? ContextBaseFileName

# --- Final Cleanup ---
# Remove the temporary 'attributes?' field and original complex fields if desired
| remove([attributes?, event, host, user, process, network, file, registry, url, http, source, destination, observer, agent, log, tags])

| @vendor := vendor ?? @vendor # Ensure top-level vendor field is set if provided
