# Zeek site-local configuration for Honeyport
# Runs on br_net_b (Cowrie's Docker bridge)

@load base/protocols/conn
@load base/protocols/ssh
@load base/protocols/http
@load base/protocols/ftp
@load base/protocols/dns
@load base/frameworks/notice
@load base/frameworks/files
@load policy/tuning/json-logs

# Log SSH brute-force attempts
@load policy/protocols/ssh/detect-bruteforcing

# Capture full payloads for file extraction
@load base/frameworks/files/extract

redef Log::default_rotation_interval = 1 hr;
redef SSH::authentication_data_max_client_size = 4096;
