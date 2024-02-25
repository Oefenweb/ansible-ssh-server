## ssh-server

[![CI](https://github.com/Oefenweb/ansible-ssh-server/workflows/CI/badge.svg)](https://github.com/Oefenweb/ansible-ssh-server/actions?query=workflow%3ACI)
[![Ansible Galaxy](http://img.shields.io/badge/ansible--galaxy-ssh--server-blue.svg)](https://galaxy.ansible.com/Oefenweb/ssh_server)

Set up an OpenSSH server in Debian-like systems.

#### Requirements

None

#### Variables

* `ssh_server_install`: [default: `[]`]: Additional packages to install

* `ssh_server_port`: [default: `22`]: Specifies the port number to connect on the remote host
* `ssh_server_protocol`: [default: `2`]: Specifies the protocol versions `ssh` should support in order of preference. The possible values are `1` and `2`. Multiple versions must be comma-separated. The default is `2,1`. This means that ssh tries version 2 and falls back to version 1 if version 2 is not available
* `ssh_server_listen_address:`: [default: `['0.0.0.0', '::']`]: Specifies the local addresses `sshd` should listen on
* `ssh_server_host_keys:`: [default: `[/etc/ssh/ssh_host_rsa_key, /etc/ssh/ssh_host_dsa_key, /etc/ssh/ssh_host_ecdsa_key, /etc/ssh/ssh_host_ed25519_key]`]: Specifies a file containing a private host key used by SSH
* `ssh_server_server_key_bits:`: [default: `1024`]: Defines the number of bits in the ephemeral protocol version 1 server key (**deprecated**)
* `ssh_server_use_privilege_separation`: [default: `true`]: Specifies whether `sshd` separates privileges by creating an unprivileged child process to deal with incoming network traffic. After successful authentication, another process will be created that has the privilege of the authenticated user. The goal of privilege separation is to prevent privilege escalation by containing any corruption within the unprivileged processes (**deprecated**)
* `ssh_server_key_regeneration_interval`: [default: `3600`]: In protocol version 1, the ephemeral server key is automatically regenerated after this many seconds (if it has been used) (**deprecated**)
* `ssh_server_syslog_facility`: [default: `AUTH`]: Gives the facility code that is used when logging messages from `sshd`
* `ssh_server_log_level`: [default: `INFO`]: Gives the verbosity level that is used when logging messages from `sshd`
* `ssh_server_login_grace_time`: [default: `120`]: The server disconnects after this time if the user has not successfully logged in
* `ssh_server_permit_root_login`: [default: `without-password`]: Specifies whether root can log in using ssh
* `ssh_server_strict_modes`: [default: `true`]: Specifies whether `sshd` should check file modes and ownership of the user's files and home directory before accepting login
* `ssh_server_rsa_authentication`: [default: `true`]: Specifies whether pure RSA authentication is allowed (**deprecated**)
* `ssh_server_pubkey_authentication`: [default: `true`]: Specifies whether public key authentication is allowed
* `ssh_server_authorized_keys_file`: [default: `'%h/.ssh/authorized_keys'`]: Specifies the file that contains the public keys that can be used for user authentication
* `ssh_server_ignore_rhosts`: [default: `true`]: Specifies that `.rhosts` and `.shosts` files will not be used
* `ssh_server_rhosts_rsa_authentication`: [default: `false`]: Specifies whether `rhosts` or `/etc/hosts.equiv` authentication together with successful RSA host authentication is allowed (**deprecated**)
* `ssh_server_hostbased_authentication`: [default: `false`]: Specifies whether `rhosts` or `/etc/hosts.equiv` authentication together with successful public key client host authentication is allowed (host-based authentication)
* `ssh_server_ignore_user_known_hosts`: [default: `false`]: Specifies whether `sshd` should ignore the user's `~/.ssh/known_hosts`
* `ssh_server_permit_empty_passwords`: [default: `false`]: When password authentication is allowed, it specifies whether the server allows login to accounts with empty password strings
* `ssh_server_challenge_response_authentication`: [default: `false`]: Specifies whether challenge-response authentication is allowed (e.g. via `PAM`)
* `ssh_server_password_authentication`: [default: `true`]: Specifies whether password authentication is allowed
* `ssh_server_kerberos_authentication`: [optional, default: `false`]: Specifies whether the password provided by the user for `PasswordAuthentication` will be validated through the Kerberos KDC
* `ssh_server_kerberos_get_afs_token`: [optional, default: `false`]: If AFS is active and the user has a Kerberos 5 TGT, attempt to acquire an AFS token before accessing the user's home directory
* `ssh_server_kerberos_or_local_passwd`: [optional, default: `true`]: If password authentication through Kerberos fails then the password will be validated via any additional local mechanism such as `/etc/passwd`
* `ssh_server_kerberos_ticket_cleanup`: [optional, default: `true`]: Specifies whether to automatically destroy the user's ticket cache file on logout
* `ssh_server_gssapi_authentication`: [optional, default: `false`]: Specifies whether user authentication based on GSSAPI is allowed
* `ssh_server_gssapi_cleanup_credentials`: [optional, default: `true`]: Specifies whether to automatically destroy the user's credentials cache on logout
* `ssh_server_gateway_ports`: [optional, default: `false`]: Specifies whether remote hosts are allowed to connect to local forwarded ports
* `ssh_server_x11_forwarding`: [default: `true`]: Specifies whether X11 forwarding is permitted
* `ssh_server_x11_display_offset`: [default: `10`]: Specifies the first display number available for `sshd`'s X11 forwarding. This prevents `sshd` from interfering with real X11 servers
* `ssh_server_print_motd`: [default: `false`]: Specifies whether `sshd` should print `/etc/motd` when a user logs in interactively
* `ssh_server_print_last_log`: [default: `true`]: Specifies whether `sshd` should print the date and time of the last user login when a user logs in interactively
* `ssh_server_tcp_keep_alive`: [default: `true`]: Specifies whether the system should send TCP keepalive messages to the other side
* `ssh_server_use_login`: [default: `false`]: Specifies whether `login` is used for interactive login sessions (**deprecated**)
* `ssh_server_max_sessions`: [default: `10`]: Allows control of the number of multiplexed sessions supported over a single TCP connection. This allows increasing the number of allowed sessions above the previous default of `10`, disabling connection multiplexing (`1`) or disallowing login/shell/subsystem sessions entirely (`0`)
* `ssh_server_max_startups`: [default: `'10:30:100'`]: Specifies the maximum number of concurrent unauthenticated connections to the SSH daemon. Additional connections will be dropped until authentication succeeds or the `LoginGraceTime` expires for a connection
* `ssh_server_banner`: [default: `none`]: The contents of the specified file are sent to the remote user before authentication is allowed
* `ssh_server_ciphers`: [optional, default: `[]`]: Specifies the ciphers allowed for protocol version 2
* `ssh_server_key_algorithms`: [optional, default: `[]`]: Specifies the available KEX (Key Exchange)	algorithms
* `ssh_server_ciphers`: [optional, default: `[]`]: Specifies the available MAC (message authentication code) algorithms. The MAC algorithm is used in protocol version 2 for data integrity protection
* `ssh_server_accept_env`: [default: `LANG LC_*`]: Specifies what environment variables sent by the client will be copied into the session's `environ`
* `ssh_server_subsystem`: [default: `sftp /usr/lib/openssh/sftp-server`]: Configures an external subsystem (e.g. file transfer daemon)
* `ssh_server_use_pam`: [default: `true`]: Enables the Pluggable Authentication Module interface
* `ssh_server_use_dns`: [default: `true`]: Specifies whether `sshd` should look up the remote host name and check that the resolved host name for the remote IP address maps back to the very same IP address
* `ssh_server_allow_groups`: [default: `[]`]: A list of group name patterns. If specified, login is allowed only for users whose primary group or supplementary group list matches one of the patterns
* `ssh_server_allow_users`: [default: `[]`]: A list of user name patterns. If specified, login is allowed only for user names that match one of the patterns
* `ssh_server_deny_groups`: [default: `[]`]: A list of group name patterns. If specified, login is disallowed for users whose primary group or supplementary group list matches one of the patterns
* `ssh_server_deny_users`: [default: `[]`]: A list of user name patterns. If specified, login is disallowed for user names that match one of the patterns
* `ssh_server_autorized_keys_command`: [default: ]: Specifies a program to be used to look up the user's public keys.
* `ssh_server_autorized_keys_command_user`: [default: `nobody`]: Specifies the user under whose account the AuthorizedKeysCommand is run


## Dependencies

None

#### Example(s)

##### Simple
```yaml
---
- hosts: all
  roles:
    - oefenweb.ssh-server
```

##### Configure security options
```yaml
---
- hosts: all
  roles:
    - oefenweb.ssh-server
  vars:
    ssh_server_ciphers:
      - aes128-ctr
      - aes192-ctr
      - aes256-ctr
      - aes128-gcm@openssh.com
      - aes256-gcm@openssh.com
      - chacha20-poly1305@openssh.com
    ssh_server_key_algorithms:
      - diffie-hellman-group-exchange-sha256
      - ecdh-sha2-nistp256
      - ecdh-sha2-nistp384
      - ecdh-sha2-nistp521
      - curve25519-sha256@libssh.org
    ssh_server_macs:
      - umac-128-etm@openssh.com
      - hmac-sha2-256-etm@openssh.com
      - hmac-sha2-512-etm@openssh.com
      - umac-128@openssh.com
      - hmac-sha2-256
      - hmac-sha2-512
```

#### License

MIT

#### Author Information

Mischa ter Smitten

#### Feedback, bug-reports, requests, ...

Are [welcome](https://github.com/Oefenweb/ansible-ssh-server/issues)!
