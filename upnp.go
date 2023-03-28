package main

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
	"time"

	"gitlab.com/NebulousLabs/fastrand"
	"gitlab.com/NebulousLabs/go-upnp/goupnp"
	"gitlab.com/NebulousLabs/go-upnp/goupnp/dcps/internetgateway1"
)

// An IGD provides an interface to the most commonly used functions of an
// Internet Gateway Device: discovering the external IP, and forwarding ports.
type IGD struct {
	// This interface is satisfied by the internetgateway1.WANIPConnection1
	// and internetgateway1.WANPPPConnection1 types.
	client interface {
		GetExternalIPAddress() (string, error)
		AddPortMapping(string, uint16, string, uint16, string, bool, string, uint32) error
		GetSpecificPortMappingEntry(string, uint16, string) (uint16, string, bool, string, uint32, error)
		DeletePortMapping(string, uint16, string) error
		GetServiceClient() *goupnp.ServiceClient
	}
}

// ExternalIP returns the router's external IP.
func (d *IGD) ExternalIP() (net.IP, error) {
	ip, err := d.client.GetExternalIPAddress()
	if err != nil {
		return nil, err
	}
	return net.ParseIP(ip), nil
}

// IsForwardedTCP checks whether a specific TCP port is forwarded to this host
func (d *IGD) IsForwardedTCP(port uint16) (bool, error) {
	return d.checkForward(port, "TCP")
}

// checkForward checks whether a specific TCP or UDP port is forwarded to this host
func (d *IGD) checkForward(port uint16, proto string) (bool, error) {
	time.Sleep(time.Millisecond)
	_, _, enabled, _, _, err := d.client.GetSpecificPortMappingEntry("", port, proto)

	if err != nil {
		// 714 "NoSuchEntryInArray" means that there is no such forwarding
		if strings.Contains(err.Error(), "<errorCode>714</errorCode>") {
			return false, nil
		}
		return false, err
	}

	return enabled, nil
}

// Forward forwards the specified port, and adds its description to the
// router's port mapping table.
func (d *IGD) Forward(port uint16, desc string) error {
	ip, err := d.getInternalIP()
	if err != nil {
		return err
	}

	time.Sleep(time.Millisecond)
	return d.client.AddPortMapping("", port, "TCP", port, ip, true, desc, 0)
}

// Clear un-forwards a port, removing it from the router's port mapping table.
func (d *IGD) Clear(port uint16) error {
	time.Sleep(time.Millisecond)
	return d.client.DeletePortMapping("", port, "TCP")
}

// Location returns the URL of the router, for future lookups (see Load).
func (d *IGD) Location() string {
	return d.client.GetServiceClient().Location.String()
}

// getInternalIP returns the user's local IP.
func (d *IGD) getInternalIP() (string, error) {
	host, _, _ := net.SplitHostPort(d.client.GetServiceClient().RootDevice.URLBase.Host)
	devIP := net.ParseIP(host)
	if devIP == nil {
		return "", errors.New("could not determine router's internal IP")
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return "", err
		}

		for _, addr := range addrs {
			if x, ok := addr.(*net.IPNet); ok && x.Contains(devIP) {
				return x.IP.String(), nil
			}
		}
	}

	return "", errors.New("could not determine internal IP")
}

// discover scans the local network for routers and returns the first
// UPnP-enabled router it encounters.  It will try up to 3 times to find a
// router, sleeping a random duration between each attempt.  This is to
// mitigate a race condition with many callers attempting to discover
// simultaneously.
func discover(ctx context.Context) (*IGD, error) {
	// TODO: if more than one client is found, only return those on the same
	// subnet as the user?
	maxTries := 3
	sleepTime := time.Millisecond * time.Duration(fastrand.Intn(5000))
	for try := 0; try < maxTries; try++ {
		pppclients, _, _ := internetgateway1.NewWANPPPConnection1Clients(ctx)
		if len(pppclients) > 0 {
			return &IGD{pppclients[0]}, nil
		}
		ipclients, _, _ := internetgateway1.NewWANIPConnection1Clients(ctx)
		if len(ipclients) > 0 {
			return &IGD{ipclients[0]}, nil
		}
		select {
		case <-ctx.Done():
			return nil, context.Canceled
		case <-time.After(sleepTime):
		}
		sleepTime *= 2
	}
	return nil, errors.New("no UPnP-enabled gateway found")
}

// Load connects to the router service specified by rawurl. This is much
// faster than Discover. Generally, Load should only be called with values
// returned by the IGD's Location method.
func Load(rawurl string) (*IGD, error) {
	loc, err := url.Parse(rawurl)
	if err != nil {
		return nil, err
	}
	pppclients, _ := internetgateway1.NewWANPPPConnection1ClientsByURL(loc)
	if len(pppclients) > 0 {
		return &IGD{pppclients[0]}, nil
	}
	ipclients, _ := internetgateway1.NewWANIPConnection1ClientsByURL(loc)
	if len(ipclients) > 0 {
		return &IGD{ipclients[0]}, nil
	}
	return nil, errors.New("no UPnP-enabled gateway found at URL " + rawurl)
}
