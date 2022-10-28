// Copyright (c) 2013-2014 The btcsuite developers
// Copyright (c) 2015-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package addrmgr

import (
	"fmt"
	"net"
	"net/netip"
)

var (
	// rfc1918Nets specifies the IPv4 private address blocks as defined by
	// by RFC1918 (10.0.0.0/8, 172.16.0.0/12, and 192.168.0.0/16).
	rfc1918Nets = []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
	}

	// rfc2544Net specifies the IPv4 block as defined by RFC2544
	// (198.18.0.0/15)
	rfc2544Net = netip.MustParsePrefix("198.18.0.0/15")

	// rfc3849Net specifies the IPv6 documentation address block as defined
	// by RFC3849 (2001:DB8::/32).
	rfc3849Net = netip.MustParsePrefix("2001:DB8::/32")

	// rfc3927Net specifies the IPv4 auto configuration address block as
	// defined by RFC3927 (169.254.0.0/16).
	rfc3927Net = netip.MustParsePrefix("169.254.0.0/16")

	// rfc3964Net specifies the IPv6 to IPv4 encapsulation address block as
	// defined by RFC3964 (2002::/16).
	rfc3964Net = netip.MustParsePrefix("2002::/16")

	// rfc4193Net specifies the IPv6 unique local address block as defined
	// by RFC4193 (FC00::/7).
	rfc4193Net = netip.MustParsePrefix("FC00::/7")

	// rfc4380Net specifies the IPv6 teredo tunneling over UDP address block
	// as defined by RFC4380 (2001::/32).
	rfc4380Net = netip.MustParsePrefix("2001::/32")

	// rfc4843Net specifies the IPv6 ORCHID address block as defined by
	// RFC4843 (2001:10::/28).
	rfc4843Net = netip.MustParsePrefix("2001:10::/28")

	// rfc4862Net specifies the IPv6 stateless address autoconfiguration
	// address block as defined by RFC4862 (FE80::/64).
	rfc4862Net = netip.MustParsePrefix("FE80::/64")

	// rfc5737Net specifies the IPv4 documentation address blocks as defined
	// by RFC5737 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
	rfc5737Net = []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
	}

	// rfc6052Net specifies the IPv6 well-known prefix address block as
	// defined by RFC6052 (64:FF9B::/96).
	rfc6052Net = netip.MustParsePrefix("64:FF9B::/96")

	// rfc6145Net specifies the IPv6 to IPv4 translated address range as
	// defined by RFC6145 (::FFFF:0:0:0/96).
	rfc6145Net = netip.MustParsePrefix("::FFFF:0:0:0/96")

	// rfc6598Net specifies the IPv4 block as defined by RFC6598 (100.64.0.0/10)
	rfc6598Net = netip.MustParsePrefix("100.64.0.0/10")

	// onionCatNet defines the IPv6 address block used to support Tor.
	// bitcoind encodes a .onion address as a 16 byte number by decoding the
	// address prior to the .onion (i.e. the key hash) base32 into a ten
	// byte number. It then stores the first 6 bytes of the address as
	// 0xfd, 0x87, 0xd8, 0x7e, 0xeb, 0x43.
	//
	// This is the same range used by OnionCat, which is part of the
	// RFC4193 unique local IPv6 range.
	//
	// In summary the format is:
	// { magic 6 bytes, 10 bytes base32 decode of key hash }
	onionCatNet = netip.MustParsePrefix("fd87:d87e:eb43::/48")

	// zero4Net defines the IPv4 address block for address staring with 0
	// (0.0.0.0/8).
	zero4Net = netip.MustParsePrefix("0.0.0.0/8")

	// heNet defines the Hurricane Electric IPv6 address block.
	heNet = netip.MustParsePrefix("2001:470::/32")

	ipv4bcast = netip.MustParseAddr("255.255.255.255")
)

// ipNet returns a net.IPNet struct given the passed IP address string, number
// of one bits to include at the start of the mask, and the total number of bits
// for the mask.
func ipNet(ip string, ones, bits int) net.IPNet {
	return net.IPNet{IP: net.ParseIP(ip), Mask: net.CIDRMask(ones, bits)}
}

// isLocal returns whether or not the given address is a local address.
func isLocal(addr netip.Addr) bool {
	return addr.IsLoopback() || zero4Net.Contains(addr)
}

// isOnionCatTor returns whether or not the passed address is in the IPv6 range
// used by bitcoin to support Tor (fd87:d87e:eb43::/48).  Note that this range
// is the same range used by OnionCat, which is part of the RFC4193 unique local
// IPv6 range.
func isOnionCatTor(addr netip.Addr) bool {
	return onionCatNet.Contains(addr)
}

// NetAddressType is used to indicate which network a network address belongs
// to.
type NetAddressType uint8

const (
	LocalAddress NetAddressType = iota
	IPv4Address
	IPv6Address
	TORv2Address
)

// addressType returns the network address type of the provided network address.
func addressType(addr netip.Addr) NetAddressType {
	switch {
	case isLocal(addr):
		return LocalAddress

	case addr.Is4():
		return IPv4Address

	case isOnionCatTor(addr):
		return TORv2Address

	default:
		return IPv6Address
	}
}

// isRFC1918 returns whether or not the passed address is part of the IPv4
// private network address space as defined by RFC1918 (10.0.0.0/8,
// 172.16.0.0/12, or 192.168.0.0/16).
func isRFC1918(addr netip.Addr) bool {
	for _, rfc := range rfc1918Nets {
		if rfc.Contains(addr) {
			return true
		}
	}
	return false
}

// isRFC2544 returns whether or not the passed address is part of the IPv4
// address space as defined by RFC2544 (198.18.0.0/15)
func isRFC2544(addr netip.Addr) bool {
	return rfc2544Net.Contains(addr)
}

// isRFC3849 returns whether or not the passed address is part of the IPv6
// documentation range as defined by RFC3849 (2001:DB8::/32).
func isRFC3849(addr netip.Addr) bool {
	return rfc3849Net.Contains(addr)
}

// isRFC3927 returns whether or not the passed address is part of the IPv4
// autoconfiguration range as defined by RFC3927 (169.254.0.0/16).
func isRFC3927(addr netip.Addr) bool {
	return rfc3927Net.Contains(addr)
}

// isRFC3964 returns whether or not the passed address is part of the IPv6 to
// IPv4 encapsulation range as defined by RFC3964 (2002::/16).
func isRFC3964(addr netip.Addr) bool {
	return rfc3964Net.Contains(addr)
}

// isRFC4193 returns whether or not the passed address is part of the IPv6
// unique local range as defined by RFC4193 (FC00::/7).
func isRFC4193(addr netip.Addr) bool {
	return rfc4193Net.Contains(addr)
}

// isRFC4380 returns whether or not the passed address is part of the IPv6
// teredo tunneling over UDP range as defined by RFC4380 (2001::/32).
func isRFC4380(addr netip.Addr) bool {
	return rfc4380Net.Contains(addr)
}

// isRFC4843 returns whether or not the passed address is part of the IPv6
// ORCHID range as defined by RFC4843 (2001:10::/28).
func isRFC4843(addr netip.Addr) bool {
	return rfc4843Net.Contains(addr)
}

// isRFC4862 returns whether or not the passed address is part of the IPv6
// stateless address autoconfiguration range as defined by RFC4862 (FE80::/64).
func isRFC4862(addr netip.Addr) bool {
	return rfc4862Net.Contains(addr)
}

// isRFC5737 returns whether or not the passed address is part of the IPv4
// documentation address space as defined by RFC5737 (192.0.2.0/24,
// 198.51.100.0/24, 203.0.113.0/24)
func isRFC5737(addr netip.Addr) bool {
	for _, rfc := range rfc5737Net {
		if rfc.Contains(addr) {
			return true
		}
	}

	return false
}

// isRFC6052 returns whether or not the passed address is part of the IPv6
// well-known prefix range as defined by RFC6052 (64:FF9B::/96).
func isRFC6052(addr netip.Addr) bool {
	return rfc6052Net.Contains(addr)
}

// isRFC6145 returns whether or not the passed address is part of the IPv6 to
// IPv4 translated address range as defined by RFC6145 (::FFFF:0:0:0/96).
func isRFC6145(addr netip.Addr) bool {
	return rfc6145Net.Contains(addr)
}

// isRFC6598 returns whether or not the passed address is part of the IPv4
// shared address space specified by RFC6598 (100.64.0.0/10)
func isRFC6598(addr netip.Addr) bool {
	return rfc6598Net.Contains(addr)
}

// isValid returns whether or not the passed address is valid.  The address is
// considered invalid under the following circumstances:
// IPv4: It is either a zero or all bits set address.
// IPv6: It is either a zero or RFC3849 documentation address.
func isValid(addr netip.Addr) bool {
	// IsUnspecified returns if address is 0, so only all bits set, and
	// RFC3849 need to be explicitly checked.
	return addr.IsValid() && !(addr.IsUnspecified() ||
		addr.Compare(ipv4bcast) == 0)
}

// IsRoutable returns whether or not the passed address is routable over
// the public internet.  This is true as long as the address is valid and is not
// in any reserved ranges.
func IsRoutable(addr netip.Addr) bool {
	return isValid(addr) && !(isRFC1918(addr) || isRFC2544(addr) ||
		isRFC3927(addr) || isRFC4862(addr) || isRFC3849(addr) ||
		isRFC4843(addr) || isRFC5737(addr) || isRFC6598(addr) ||
		isLocal(addr) || (isRFC4193(addr) && !isOnionCatTor(addr)))
}

// GroupKey returns a string representing the network group an address is part
// of.  This is the /16 for IPv4, the /32 (/36 for he.net) for IPv6, the string
// "local" for a local address, the string "tor:key" where key is the /4 of the
// onion address for Tor address, and the string "unroutable" for an unroutable
// address.
func (na *NetAddress) GroupKey() string {
	netIP := na.IP
	if isLocal(netIP) {
		return "local"
	}
	if !IsRoutable(netIP) {
		return "unroutable"
	}
	if netIP.Is4() {
		return netip.PrefixFrom(netIP, 16).Masked().Addr().String()
	}
	if isRFC6145(netIP) || isRFC6052(netIP) {
		// last four bytes are the ip address
		b := netIP.As16()
		newB := b[12:16]
		newIP, _ := netip.AddrFromSlice(newB)

		return netip.PrefixFrom(newIP, 16).Masked().Addr().String()
	}

	if isRFC3964(netIP) {
		b := netIP.As16()
		newB := b[2:6]
		newIP, _ := netip.AddrFromSlice(newB)
		return netip.PrefixFrom(newIP, 16).Masked().Addr().String()
	}
	if isRFC4380(netIP) {
		// teredo tunnels have the last 4 bytes as the v4 address XOR
		// 0xff.
		b := netIP.As16()
		var newB [4]byte
		for i, byte := range b[12:16] {
			newB[i] = byte ^ 0xff
		}
		newIP, _ := netip.AddrFromSlice(newB[:])
		return netip.PrefixFrom(newIP, 16).Masked().Addr().String()
	}
	if isOnionCatTor(netIP) {
		// group is keyed off the first 4 bits of the actual onion key.
		b := netIP.As16()
		return fmt.Sprintf("tor:%d", b[6]&((1<<4)-1))
	}

	// OK, so now we know ourselves to be a IPv6 address.
	// bitcoind uses /32 for everything, except for Hurricane Electric's
	// (he.net) IP range, which it uses /36 for.
	bits := 32
	if heNet.Contains(netIP) {
		bits = 36
	}
	return netip.PrefixFrom(netIP, bits).Masked().Addr().String()
}
