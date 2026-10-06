pkgname=swat
pkgver=0.1.0
pkgrel=1
pkgdesc='Under-construction Arch Linux server dashboard'
arch=('x86_64' 'aarch64')
url='https://github.com/Evohl/S.W.A.T'
license=('unknown')
options=('!debug')
depends=('glibc' 'pam' 'systemd')
makedepends=('go' 'gcc')
optdepends=(
	'iproute2: network interface information'
	'nftables: firewall inspection'
	'libvirt: virtual machine inventory and management'
)

build() {
	cd "$startdir"
	go test ./cmd/... ./internal/...
	CGO_ENABLED=1 go build -trimpath -buildmode=pie -o "$srcdir/swat" ./cmd/swat
}

package() {
	install -Dm755 "$srcdir/swat" "$pkgdir/usr/bin/swat"
	install -Dm644 "$startdir/packaging/swat.service" "$pkgdir/usr/lib/systemd/system/swat.service"
	install -Dm644 "$startdir/packaging/swat.sysusers.conf" "$pkgdir/usr/lib/sysusers.d/swat.conf"
	install -Dm644 "$startdir/README.md" "$pkgdir/usr/share/doc/swat/README.md"
	install -Dm644 "$startdir/cmd/swat/web/static/vendor/spice-html5/COPYING.LESSER" "$pkgdir/usr/share/licenses/swat/vendor-spice-html5-COPYING.LESSER"
}
