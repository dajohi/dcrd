package main

import (
	"github.com/huin/goupnp/dcps/internetgateway1"
)

func discover() (*internetgateway1.WANPPPConnection1, error) {
	clients, upnperrors, err := internetgateway1.NewWANPPPConnection1Clients()
	if err != nil {
		return nil, err
	}
	for i := range upnperrors {
		srvrLog.Debugf("UPNP error: %v", upnperrors[i])
	}
	if len(clients) == 0 {
		// no upnp available.
		return nil, nil
	}

	for i := range clients {
		srv := clients[i].ServiceClient.Service
		desc, err := srv.RequestSCPD()
		if err != nil {
			srvrLog.Errorf("UPNP: failed to request services: %v", err)
			continue
		}

		valid := desc.GetAction("AddPortMapping") != nil &&
			desc.GetAction("DeletePortMapping") != nil &&
			desc.GetAction("GetExternalIPAddress") != nil

		if !valid {
			srvrLog.Debugf("UPNP: service is missing requirements")
			continue
		}

		// return first acceptable
		return clients[i], nil
	}

	return nil, nil
}
