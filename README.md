## ssh-server

[![Build Status](https://travis-ci.org/Oefenweb/ansible-ssh-server.svg?branch=master)](https://travis-ci.org/Oefenweb/ansible-ssh-server) [![Ansible Galaxy](http://img.shields.io/badge/ansible--galaxy-ssh--server-blue.svg)](https://galaxy.ansible.com/list#/roles/4191)

Set up an OpenSSH server in Debian-like systems.

#### Requirements

None

#### Variables

* `ssh_server_install`: [default: `[]`]: Additional packages to install

* `ssh_server_port`: [default: `22`]: Specifies the port number to connect on the remote host 
* `ssh_server_protocol`: [default: `2`]: Specifies the protocol versions `ssh` should support in order of preference. The possible values are `1` and `2`. Multiple versions must be comma-separated. The default is `2,1`.  This means that ssh tries version 2 and falls back to version 1 if version 2 is not available
* `ssh_server_listen_address:`: [default: `['0.0.0.0', '::']`]: Specifies the local addresses `sshd` should listen on
* `ssh_server_host_keys:`: [default: `[/etc/ssh/ssh_host_rsa_key, /etc/ssh/ssh_host_dsa_key, /etc/ssh/ssh_host_ecdsa_key, /etc/ssh/ssh_host_ed25519_key]` depending on OS version, see `defaults/main.yml`]: Specifies a file containing a private host key used by SSH
* `ssh_server_server_key_bits:`: [default: `1024` or `768` depending on OS version, see `defaults/main.yml`]: Defines the number of bits in the ephemeral protocol version 1 server key
* `ssh_server_use_privilege_separation`: [default: `true`]: Specifies whether `sshd` separates privileges by creating an unprivileged child process to deal with incoming network traffic. After successful authentication, another process will be created that has the privilege of the authenticated user. The goal of privilege separation is to prevent privilege escalation by containing any corruption within the unprivileged processes
* `ssh_server_key_regeneration_interval`: [default: `3600`]: In protocol version 1, the ephemeral server key is automatically regenerated after this many seconds (if it has been used)
* `ssh_server_syslog_facility`: [default: `AUTH`]: Gives the facility code that is used when logging messages from `sshd`
* `ssh_server_log_level`: [default: `INFO`]: Gives the verbosity level that is used when logging messages from `sshd`
* `ssh_server_login_grace_time`: [default: `120`]: The server disconnects after this time if the user has not successfully logged in
* `ssh_server_permit_root_login`: [default: `without-password` or `yes` depending on OS version, see `defaults/main.yml`]: Specifies whether root can log in using ssh
* `ssh_server_strict_modes`: [default: `true`]: Specifies whether `sshd` should check file modes and ownership of the user's files and home directory before accepting login
* `ssh_server_rsa_authentication`: [default: `true`]:  Specifies whether pure RSA authentication is allowed
* `ssh_server_pubkey_authentication`: [default: `true`]: Specifies whether public key authentication is allowed
* `ssh_server_authorized_keys_file`: [default: `'%h/.ssh/authorized_keys'`]: Specifies the file that contains the public keys that can be used for user authentication
* `ssh_server_ignore_rhosts`: [default: `true`]: Specifies that `.rhosts` and `.shosts` files will not be used
* `ssh_server_rhosts_rsa_authentication`: [default: `false`]: Specifies whether `rhosts` or `/etc/hosts.equiv` authentication together with successful RSA host authentication is allowed
* `ssh_server_hostbased_authentication`: [default: `false`]: Specifies whether `rhosts` or `/etc/hosts.equiv` authentication together with successful public key client host authentication is allowed (host-based authentication)
* `ssh_server_ignore_user_known_hosts`: [default: `false`]: Specifies whether `sshd` should ignore the user's `~/.ssh/known_hosts`
* `ssh_server_permit_empty_passwords`: [default: `false`]: When password authentication is allowed, it specifies whether the server allows login to accounts with empty password strings
* `ssh_server_challenge_response_authentication`: [default: `false`]: Specifies whether challenge-response authentication is allowed (e.g. via `PAM`)
* `ssh_server_password_authentication`: [default: `true`]: Specifies whether password authentication is allowed
* `ssh_server_kerberos_authentication`: [default: `false`]:
* `ssh_server_kerberos_get_afs_token`: [default: `false`]:
* `ssh_server_kerberos_or_local_passwd`: [default: `true`]:
* `ssh_server_kerberos_ticket_cleanup`: [default: `true`]:
* `ssh_server_gssapi_authentication`: [default: `false`]:
* `ssh_server_gssapi_cleanup_credentials`: [default: `true`]:
* `ssh_server_x11_forwarding`: [default: `true`]:
* `ssh_server_x11_display_offset`: [default: `10`]:
* `ssh_server_print_motd`: [default: `false`]:
* `ssh_server_print_last_log`: [default: `true`]:
* `ssh_server_tcp_keep_alive`: [default: `true`]:
* `ssh_server_use_login`: [default: `false`]:
* `ssh_server_max_startups`: [default: `'10:30:60'`]:
* `ssh_server_banner`: [default: `none`]:
* `ssh_server_accept_env`: [default: `LANG LC_*`]:
* `ssh_server_subsystem`: [default: `sftp /usr/lib/openssh/sftp-server`]:
* `ssh_server_use_pam`: [default: `true`]:
* `ssh_server_use_dns`: [default: `true`]:
* `ssh_server_allow_groups`: [default: `[]`]:
* `ssh_server_allow_users`: [default: `[]`]:
* `ssh_server_deny_groups`: [default: `[]`]:
* `ssh_server_deny_users`: [default: `[]`]:

## Dependencies

None

#### Example

```yaml
---
- hosts: all
  roles:
  - ssh-server
```

#### License

MIT

#### Author Information

Mischa ter Smitten

#### Feedback, bug-reports, requests, ...

Are [welcome](https://github.com/Oefenweb/ansible-ssh-server/issues)!
