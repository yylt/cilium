// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package staticip

import (
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Module(
	"ipam-staticip-manager",
	"Provides IPAM staticip",

	cell.Provide(newStaticIPManager),
)

type managerParams struct {
	cell.In

	Lifecycle    hive.Lifecycle
	DaemonConfig *option.DaemonConfig
	Clientset    client.Clientset
}

func newStaticIPManager(params managerParams) *Manager {
	if params.DaemonConfig.IPAM == ipamOption.IPAMOpenStack {
		manager := &Manager{
			StaticIPInterface: params.Clientset.CiliumV2alpha1(),
			stop:              make(chan struct{}),
		}
		params.Lifecycle.Append(manager)
		return manager
	}
	return nil
}
