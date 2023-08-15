// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"fmt"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	v2alpha12 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	slimclientset "github.com/cilium/cilium/pkg/k8s/slim/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/k8s/utils"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/cache"
	"strings"
	"sync"
	"time"
)

var (
	// slimNodeStore contains all cluster nodes store as slim_core.Node
	slimNodeStore cache.Store

	// crdPoolStore contains all cluster pool store as v2alpha1.CiliumPodIPPool
	crdPoolStore cache.Store

	// crdPoolStore contains all cluster csip store as v2alpha1.CiliumStaticIP
	staticIPStore cache.Store

	nodeController     cache.Controller
	poolController     cache.Controller
	staticIPController cache.Controller

	// multiPoolExtraSynced is closed once the slimNodeStore and crdPoolStore is synced
	// with k8s.
	multiPoolExtraSynced = make(chan struct{})

	queueKeyFunc = cache.DeletionHandlingMetaNamespaceKeyFunc

	// multiPoolExtraInit initialize the k8sManager
	multiPoolExtraInit sync.Once

	k8sManager = extraManager{reSyncMap: map[*Node]struct{}{}}

	// node to pool map
	nodeToPools map[string]poolSet

	// pool to node map
	poolsToNodes map[string]set
)

const (
	Deleted poolState = iota
	InUse
	Updated
)

type set map[string]struct{}
type poolSet map[string]poolState
type poolState int

const (
	poolAnnotation = "ipam.cilium.io/openstack-ip-pool"
	poolLabel      = "openstack-ip-pool"
)

type extraOperation interface {
	ListK8sSlimNode() []*slim_corev1.Node
	GetK8sSlimNode(nodeName string) (*slim_corev1.Node, error)
	LabelNodeWithPool(nodeName string, labels map[string]string) error
	ListCiliumIPPool() []*v2alpha1.CiliumPodIPPool
	updateCiliumNodeManagerPool()
	listStaticIPs() []*v2alpha1.CiliumStaticIP
}

func InitIPAMOpenStackExtra(slimClient slimclientset.Interface, alphaClient v2alpha12.CiliumV2alpha1Interface, stopCh <-chan struct{}) {
	multiPoolExtraInit.Do(func() {
		nodeToPools = map[string]poolSet{}
		poolsToNodes = map[string]set{}

		nodesInit(slimClient, stopCh)
		poolsInit(alphaClient, stopCh)

		k8sManager.client = slimClient
		k8sManager.alphaClient = alphaClient

		k8sManager.updateCiliumNodeManagerPool()

		close(multiPoolExtraSynced)
	})

}

// nodesInit starts up a node watcher to handle node events.
func nodesInit(slimClient slimclientset.Interface, stopCh <-chan struct{}) {
	slimNodeStore, nodeController = informer.NewInformer(
		utils.ListerWatcherFromTyped[*slim_corev1.NodeList](slimClient.CoreV1().Nodes()),
		&slim_corev1.Node{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				updateNode(obj)
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				// little optimize for invoke updateNode
				if compareNodeAnnotationAndLabelChange(oldObj, newObj) {
					updateNode(newObj)
				}
			},
		},
		transformToNode,
	)
	go func() {
		nodeController.Run(stopCh)
	}()

	cache.WaitForCacheSync(stopCh, nodeController.HasSynced)
}

// poolsInit starts up a node watcher to handle pool events.
func poolsInit(poolGetter v2alpha12.CiliumPodIPPoolsGetter, stopCh <-chan struct{}) {
	crdPoolStore, poolController = informer.NewInformer(
		utils.ListerWatcherFromTyped[*v2alpha1.CiliumPodIPPoolList](poolGetter.CiliumPodIPPools()),
		&v2alpha1.CiliumPodIPPool{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				updatePool(obj)
			},
			UpdateFunc: func(_, newObj interface{}) {
				updatePool(newObj)
			},
			DeleteFunc: func(obj interface{}) {
				deletePool(obj)
			},
		},
		transformToPool,
	)
	go func() {
		poolController.Run(stopCh)
	}()

	cache.WaitForCacheSync(stopCh, poolController.HasSynced)
}

// extraManager defines a manager responds for sync csip and pool
type extraManager struct {
	nodeManager *NodeManager
	client      slimclientset.Interface
	alphaClient v2alpha12.CiliumV2alpha1Interface
	updateMutex sync.Mutex
	reSync      bool
	reSyncMap   map[*Node]struct{}
}

// ListCiliumIPPool returns all the *v2alpha1.CiliumPodIPPool from crdPoolStore
func (extraManager) ListCiliumIPPool() []*v2alpha1.CiliumPodIPPool {
	poolsInt := crdPoolStore.List()
	out := make([]*v2alpha1.CiliumPodIPPool, 0, len(poolsInt))
	for i := range poolsInt {
		out = append(out, poolsInt[i].(*v2alpha1.CiliumPodIPPool))
	}
	return out
}

// ListK8sSlimNode returns all the *slim_corev1.Node from slimNodeStore
func (extraManager) ListK8sSlimNode() []*slim_corev1.Node {
	nodesInt := slimNodeStore.List()
	out := make([]*slim_corev1.Node, 0, len(nodesInt))
	for i := range nodesInt {
		out = append(out, nodesInt[i].(*slim_corev1.Node))
	}
	return out
}

// GetK8sSlimNode returns *slim_corev1.Nod by nodeName which stored in slimNodeStore
func (extraManager) GetK8sSlimNode(nodeName string) (*slim_corev1.Node, error) {
	nodeInterface, exists, err := slimNodeStore.GetByKey(nodeName)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, k8sErrors.NewNotFound(schema.GroupResource{
			Group:    "core",
			Resource: "Node",
		}, nodeName)
	}
	return nodeInterface.(*slim_corev1.Node), nil
}

// LabelNodeWithPool relabel the node with provided labels map
func (extraManager) LabelNodeWithPool(nodeName string, labels map[string]string) error {
	oldNode, err := k8sManager.client.CoreV1().Nodes().Get(context.Background(), nodeName, v1.GetOptions{})
	if err != nil {
		return err
	}
	oldLabel := oldNode.GetLabels()

	// remove all the old pool label
	for k, _ := range oldLabel {
		if strings.HasPrefix(k, poolLabel) {
			delete(oldLabel, k)
		}
	}

	// label all the updated pool
	for k, v := range labels {
		oldLabel[k] = v
	}
	oldNode.SetLabels(oldLabel)
	_, err = k8sManager.client.CoreV1().Nodes().Update(context.Background(), oldNode, v1.UpdateOptions{})
	return err
}

func compareNodeAnnotationAndLabelChange(oldObj, newObj interface{}) bool {
	oldAccessor, _ := meta.Accessor(oldObj)
	newAccessor, _ := meta.Accessor(newObj)
	if oldAccessor.GetAnnotations()[poolAnnotation] != newAccessor.GetAnnotations()[poolAnnotation] {
		return true
	}
	return false
}

func (extraManager) updateCiliumNodeManagerPool() {
	for _, ipPool := range k8sManager.ListCiliumIPPool() {
		k8sManager.nodeManager.pools[ipPool.Name] = ipPool
	}
}

func transformToNode(obj interface{}) (interface{}, error) {
	switch concreteObj := obj.(type) {
	case *slim_corev1.Node:
		n := &slim_corev1.Node{
			TypeMeta: concreteObj.TypeMeta,
			ObjectMeta: slim_metav1.ObjectMeta{
				Name:            concreteObj.Name,
				ResourceVersion: concreteObj.ResourceVersion,
				Annotations:     concreteObj.Annotations,
				Labels:          concreteObj.Labels,
			},
			Spec: slim_corev1.NodeSpec{
				Taints: concreteObj.Spec.Taints,
			},
			Status: slim_corev1.NodeStatus{
				Conditions: concreteObj.Status.Conditions,
			},
		}
		*concreteObj = slim_corev1.Node{}
		return n, nil
	case cache.DeletedFinalStateUnknown:
		node, ok := concreteObj.Obj.(*slim_corev1.Node)
		if !ok {
			return nil, fmt.Errorf("unknown object type %T", concreteObj.Obj)
		}
		dfsu := cache.DeletedFinalStateUnknown{
			Key: concreteObj.Key,
			Obj: &slim_corev1.Node{
				TypeMeta: node.TypeMeta,
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:            node.Name,
					ResourceVersion: node.ResourceVersion,
					Annotations:     node.Annotations,
					Labels:          node.Labels,
				},
				Spec: slim_corev1.NodeSpec{
					Taints: node.Spec.Taints,
				},
				Status: slim_corev1.NodeStatus{
					Conditions: node.Status.Conditions,
				},
			},
		}
		// Small GC optimization
		*node = slim_corev1.Node{}
		return dfsu, nil
	default:
		return nil, fmt.Errorf("unknown object type %T", concreteObj)
	}
}

func transformToPool(obj interface{}) (interface{}, error) {
	switch concreteObj := obj.(type) {
	case *v2alpha1.CiliumPodIPPool:
		n := &v2alpha1.CiliumPodIPPool{
			TypeMeta: concreteObj.TypeMeta,
			ObjectMeta: v1.ObjectMeta{
				Name:            concreteObj.Name,
				ResourceVersion: concreteObj.ResourceVersion,
			},
			Spec: v2alpha1.IPPoolSpec{
				SubnetId: concreteObj.Spec.SubnetId,
			},
		}
		*concreteObj = v2alpha1.CiliumPodIPPool{}
		return n, nil
	case cache.DeletedFinalStateUnknown:
		p, ok := concreteObj.Obj.(*v2alpha1.CiliumPodIPPool)
		if !ok {
			return nil, fmt.Errorf("unknown object type %T", concreteObj.Obj)
		}
		dfsu := cache.DeletedFinalStateUnknown{
			Key: concreteObj.Key,
			Obj: &v2alpha1.CiliumPodIPPool{
				TypeMeta: p.TypeMeta,
				ObjectMeta: v1.ObjectMeta{
					Name:            p.Name,
					ResourceVersion: p.ResourceVersion,
				},
				Spec: v2alpha1.IPPoolSpec{
					SubnetId: p.Spec.SubnetId,
				},
			},
		}
		// Small GC optimization
		*p = v2alpha1.CiliumPodIPPool{}
		return dfsu, nil
	default:
		return nil, fmt.Errorf("unknown object type %T", concreteObj)
	}
}

func updatePool(obj interface{}) {
	key, _ := queueKeyFunc(obj)
	p, exists, err := crdPoolStore.GetByKey(key)
	if err != nil {
		log.Errorf("waring: crd pool store get pool: %s error %s", key, err)
	}
	if !exists {
		return
	}
	if poolsToNodes[key] == nil {
		poolsToNodes[key] = map[string]struct{}{}
	} else {
		for node, _ := range poolsToNodes[key] {
			if k8sManager.nodeManager.pools[key].Spec.SubnetId != p.(*v2alpha1.CiliumPodIPPool).Spec.SubnetId {
				nodeToPools[node][key] = Updated
			}
		}
	}
	k8sManager.nodeManager.pools[key] = p.(*v2alpha1.CiliumPodIPPool)

}

func deletePool(obj interface{}) {
	key, _ := queueKeyFunc(obj)
	delete(k8sManager.nodeManager.pools, key)
}

func updateNode(obj interface{}) {
	key, _ := queueKeyFunc(obj)
	var retryCount int
loop:
	node, ok := k8sManager.nodeManager.nodes[key]
	if !ok && retryCount < 3 {
		<-time.After(1 * time.Second)
		retryCount++
		goto loop
	}
	if ok {
		err := k8sManager.nodeManager.SyncMultiPool(node)
		if err != nil {
			log.Error(err)
		}
	}
}
