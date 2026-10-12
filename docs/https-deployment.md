# Public HTTPS Deployment

The packaged service listens on IPv4 interfaces at `0.0.0.0:8443` using
HTTPS directly through Go's standard HTTP server; Nginx is not required. On
first start, it creates and persists a self-signed certificate and private key
under `$SWAT_STATE_DIR/tls` (in the package, `/var/lib/swat/tls`). The key is
mode 0600 and the directory is mode 0700. The certificate includes the system
hostname and local interface IP addresses. Set `SWAT_TLS_SERVER_NAME` in a
systemd drop-in before first start if clients will connect through a public IP
or DNS name not assigned locally. HTTP is not redirected; no public HTTP
listener is started.

SWAT is an unfinished administrative service. The self-signed certificate
encrypts traffic but does not authenticate the server; browsers show a
certificate warning. TLS does not make public exposure risk-free. Prefer a VPN
or restrict TCP 8443 to trusted source addresses. No firewall rules are changed
automatically.

## Requirements

- The generated certificate covers the host name and local IP addresses; no
  domain is required for an initial test. If connecting through a NAT/public
  address not assigned to a local interface, configure that address with
  `SWAT_TLS_SERVER_NAME` before first start or replace the certificate later.
- The package does not change the firewall. Allow inbound TCP 8443 only after
  inspecting the active firewall manager, and preserve the existing SSH rule.
  Do not assume firewalld and nftables are interchangeable.

## Custom Certificate

To use a browser-trusted certificate later, obtain one from an ACME client.
For Certbot's standalone HTTP-01 challenge, TCP 80 must reach the host while
issuing or renewing the certificate. DNS-01 can be used when inbound TCP 80
must remain closed. Replace `swat.example.net` with the certificate name.

For a new HTTP-01 certificate on Arch, first ensure DNS points to this host and
TCP 80 can reach it, then run:

```bash
sudo pacman -S --needed certbot
sudo certbot certonly --standalone --preferred-challenges http -d swat.example.net
```

Create a service drop-in with `sudo systemctl edit swat.service`. Reset the
packaged credential entries, then point systemd at the custom files; do not
loosen private-key file permissions:

```ini
[Service]
LoadCredential=
LoadCredential=swat-cert:/etc/letsencrypt/live/swat.example.net/fullchain.pem
LoadCredential=swat-key:/etc/letsencrypt/live/swat.example.net/privkey.pem
Environment=SWAT_TLS_CERT=%d/swat-cert
Environment=SWAT_TLS_KEY=%d/swat-key
```

Apply and check the service:

```bash
sudo systemctl daemon-reload
sudo systemctl restart swat.service
sudo systemctl --no-pager status swat.service
```

Restart SWAT and open `https://swat.example.net:8443/`. The session cookie is
automatically marked `Secure` for both generated and custom TLS.

## Renewal

Systemd credentials are refreshed when the service starts. Configure the
Certbot deploy hook at
`/etc/letsencrypt/renewal-hooks/deploy/50-restart-swat` to run:

```sh
#!/bin/sh
systemctl restart swat.service
```

Make the hook executable with `sudo chmod 755
/etc/letsencrypt/renewal-hooks/deploy/50-restart-swat`, then enable Arch's
renewal timer with `sudo systemctl enable --now certbot-renew.timer`. Without
the restart, SWAT continues serving the certificate copied at its previous
start.