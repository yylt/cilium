// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"fmt"
	"strings"
	"time"
)

func (n *NodeManager) resyncNodeV2(ctx context.Context, node *Node, stats *resyncStats, syncTime time.Time) {
	node.updateLastResyncV2(syncTime)
	node.recalculateV2()
	allocationNeeded := node.allocationNeededV2()
	releaseNeeded := node.releaseNeededV2()
	if allocationNeeded || releaseNeeded {
		node.requirePoolMaintenanceV2()
		node.poolMaintainer.Trigger()
	}

	nodeStats := node.Stats()

	stats.mutex.Lock()
	stats.totalUsed += nodeStats.UsedIPs
	// availableOnNode is the number of available IPs on the node at this
	// current moment. It does not take into account the number of IPs that
	// can be allocated in the future.
	availableOnNode := nodeStats.AvailableIPs - nodeStats.UsedIPs
	stats.totalAvailable += availableOnNode
	stats.totalNeeded += nodeStats.NeededIPs
	stats.remainingInterfaces += nodeStats.RemainingInterfaces
	stats.interfaceCandidates += nodeStats.InterfaceCandidates
	stats.emptyInterfaceSlots += nodeStats.EmptyInterfaceSlots
	stats.nodes++

	stats.nodeCapacity = nodeStats.Capacity

	// Set per Node metrics.
	n.metricsAPI.SetIPAvailable(node.name, stats.nodeCapacity)
	n.metricsAPI.SetIPUsed(node.name, nodeStats.UsedIPs)
	n.metricsAPI.SetIPNeeded(node.name, nodeStats.NeededIPs)

	if allocationNeeded {
		stats.nodesInDeficit++
	}

	if nodeStats.RemainingInterfaces == 0 && availableOnNode == 0 {
		stats.nodesAtCapacity++
	}

	stats.mutex.Unlock()

	node.k8sSync.Trigger()
}

// SyncMultiPool labels the node with "openstack-ip-pool" when a ciliumNode upsert or a k8s node's pool annotation changed.
func (n *NodeManager) SyncMultiPool(node *Node) error {
	sNode, err := k8sManager.GetK8sSlimNode(node.name)
	if err != nil {
		return fmt.Errorf("warning: get k8s node failed: %v ", err)
	}
	if sNode.Annotations != nil {
		if pools := strings.Split(sNode.Annotations[poolAnnotation], ","); len(pools) > 0 {
			labels := map[string]string{}
			for _, p := range pools {
				if poolCrd := n.pools[p]; poolCrd != nil {
					if node.pools[Pool(p)] == nil {
						node.pools[Pool(p)] = NewCrdPool(Pool(p), node, n.releaseExcessIPs)
						if nodeToPools[sNode.Name] == nil {
							nodeToPools[sNode.Name] = poolSet{}
						}
						nodeToPools[sNode.Name][p] = InUse
						if poolsToNodes[p] == nil {
							poolsToNodes[p] = map[string]struct{}{}
						}
						poolsToNodes[p][sNode.Name] = struct{}{}
					}
					labels[poolLabel+"/"+p] = "true"
				}
			}
			if len(labels) > 0 {
				err := k8sManager.LabelNodeWithPool(node.name, labels)
				if err != nil {
					return fmt.Errorf("label node %s failed: %v", sNode.Name, err)
				}
			}
		}
	}
	return nil
}
