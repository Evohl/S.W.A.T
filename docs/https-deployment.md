# Public HTTPS Deployment

The packaged service remains bound to `127.0.0.1:8443` unless explicitly
configured. The server refuses to start on a non-loopback address without
both a TLS certificate and key. It serves HTTPS directly through Go's standard
HTTP server; Nginx is not required. HTTP is not redirected because no public
HTTP listener is started.

SWAT is an unfinished administrative service. TLS protects credentials in
transit but does not make public exposure risk-free. Prefer a VPN or restrict
TCP 443 to trusted source addresses. The package remains read-only and no
firewall rules are changed automatically.

## Requirements

- Use a DNS name with an `A` record pointing to the server. Publish an `AAAA`
  record only if IPv6 routing and firewall access are also configured.
- Obtain a browser-trusted certificate for that name. For Certbot's standalone
  HTTP-01 challenge, TCP 80 must reach the host while issuing or renewing the
  certificate. DNS-01 can be used when inbound TCP 80 must remain closed.
- Allow inbound TCP 443 in the active firewall while preserving the existing
  SSH rule. Inspect the active firewall manager first; do not replace its rules
  or assume firewalld and nftables are interchangeable.

## Configure TLS

The example uses Certbot certificate paths. Replace `swat.example.net` with
the actual certificate name. Do not change permissions on `privkey.pem` to
make it readable by the `swat` account; systemd copies both files into the
service's protected credential directory at start.

For a new HTTP-01 certificate on Arch, first ensure DNS points to this host and
TCP 80 can reach it, then run:

```bash
sudo pacman -S --needed certbot
sudo certbot certonly --standalone --preferred-challenges http -d swat.example.net
```

Create a service drop-in with `sudo systemctl edit swat.service`:

```ini
[Service]
LoadCredential=swat-cert:/etc/letsencrypt/live/swat.example.net/fullchain.pem
LoadCredential=swat-key:/etc/letsencrypt/live/swat.example.net/privkey.pem
Environment=SWAT_TLS_CERT=%d/swat-cert
Environment=SWAT_TLS_KEY=%d/swat-key
Environment=SWAT_ADDR=0.0.0.0:443
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

`CAP_NET_BIND_SERVICE` lets the unprivileged service bind port 443. To avoid
that capability, use a port above 1024, such as `8443`, and include that port
in the URL and firewall rule instead.

Apply and check the service:

```bash
sudo systemctl daemon-reload
sudo systemctl restart swat.service
sudo systemctl --no-pager status swat.service
```

Open `https://swat.example.net/`. The session cookie is automatically marked
`Secure` when both TLS variables are configured. When TLS terminates at a
trusted proxy instead, set `SWAT_COOKIE_SECURE=1` in the service drop-in.

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