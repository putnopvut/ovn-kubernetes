package ovn

import (
	"github.com/openvswitch/ovn-kubernetes/go-controller/pkg/factory"
	"github.com/openvswitch/ovn-kubernetes/go-controller/pkg/kube"
	util "github.com/openvswitch/ovn-kubernetes/go-controller/pkg/util"
	"github.com/sirupsen/logrus"
	kapi "k8s.io/api/core/v1"
	kapisnetworking "k8s.io/api/networking/v1"
	kv1core "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/apimachinery/pkg/types"
	"reflect"
	"sync"
	"time"
	"encoding/json"
	"errors"
)

// Key used for looking up service namespace information for a particular
// load balancer
type ServiceVIPKey struct {
	// Load balancer VIP in the form "ip:port"
	vip string
	// Protocol used by the load balancer
	protocol kapi.Protocol
}

// Controller structure is the object which holds the controls for starting
// and reacting upon the watched resources (e.g. pods, endpoints)
type Controller struct {
	kube           kube.Interface
	nodePortEnable bool
	watchFactory   *factory.WatchFactory

	gatewayCache map[string]string
	// For TCP and UDP type traffic, cache OVN load-balancers used for the
	// cluster's east-west traffic.
	loadbalancerClusterCache map[string]string

	// For TCP and UDP type traffice, cache OVN load balancer that exists on the
	// default gateway
	loadbalancerGWCache map[string]string

	// A cache of all logical switches seen by the watcher
	logicalSwitchCache map[string]bool

	// A cache of all logical ports seen by the watcher and
	// its corresponding logical switch
	logicalPortCache map[string]string

	// A cache of all logical ports and its corresponding uuids.
	logicalPortUUIDCache map[string]string

	// For each namespace, an address_set that has all the pod IP
	// address in that namespace
	namespaceAddressSet map[string]map[string]bool

	// For each namespace, a lock to protect critical regions
	namespaceMutex map[string]*sync.Mutex

	// For each namespace, a map of policy name to 'namespacePolicy'.
	namespacePolicies map[string]map[string]*namespacePolicy

	// Port group for ingress deny rule
	portGroupIngressDeny string

	// Port group for egress deny rule
	portGroupEgressDeny string

	// For each logical port, the number of network policies that want
	// to add a ingress deny rule.
	lspIngressDenyCache map[string]int

	// For each logical port, the number of network policies that want
	// to add a egress deny rule.
	lspEgressDenyCache map[string]int

	// A mutex for lspIngressDenyCache and lspEgressDenyCache
	lspMutex *sync.Mutex

	// A mutex for gatewayCache and logicalSwitchCache which holds
	// logicalSwitch information
	lsMutex *sync.Mutex

	// supports port_group?
	portGroupSupport bool

	// Map of load balancers to service namespace
	serviceVIPToName map[ServiceVIPKey]types.NamespacedName

	serviceVIPToNameLock *sync.Mutex
}

const (
	// TCP is the constant string for the string "TCP"
	TCP = "TCP"

	// UDP is the constant string for the string "UDP"
	UDP = "UDP"
)

// NewOvnController creates a new OVN controller for creating logical network
// infrastructure and policy
func NewOvnController(kubeClient kubernetes.Interface, wf *factory.WatchFactory, nodePortEnable bool) *Controller {
	return &Controller{
		kube:                     &kube.Kube{KClient: kubeClient},
		watchFactory:             wf,
		logicalSwitchCache:       make(map[string]bool),
		logicalPortCache:         make(map[string]string),
		logicalPortUUIDCache:     make(map[string]string),
		namespaceAddressSet:      make(map[string]map[string]bool),
		namespacePolicies:        make(map[string]map[string]*namespacePolicy),
		namespaceMutex:           make(map[string]*sync.Mutex),
		lspIngressDenyCache:      make(map[string]int),
		lspEgressDenyCache:       make(map[string]int),
		lspMutex:                 &sync.Mutex{},
		lsMutex:                  &sync.Mutex{},
		gatewayCache:             make(map[string]string),
		loadbalancerClusterCache: make(map[string]string),
		loadbalancerGWCache:      make(map[string]string),
		nodePortEnable:           nodePortEnable,
		serviceVIPToName:         make(map[ServiceVIPKey]types.NamespacedName),
		serviceVIPToNameLock:     &sync.Mutex{},
	}
}

// Run starts the actual watching. Also initializes any local structures needed.
func (oc *Controller) Run(stopChan chan struct{}) error {
	_, _, err := util.RunOVNNbctl("--columns=_uuid", "list",
		"port_group")
	if err == nil {
		oc.portGroupSupport = true
	}

	for _, f := range []func() error{oc.WatchPods, oc.WatchServices, oc.WatchEndpoints, oc.WatchNamespaces,
		oc.WatchNetworkPolicy, oc.WatchNodes} {
		if err := f(); err != nil {
			return err
		}
	}

	go oc.EventChecker(stopChan)
	return nil
}

type Record struct {
	Data [][]interface{}
	Headings []string
}

type emptyLBBackendEvent struct {
	vip string
	protocol kapi.Protocol
	uuid string
}

func ExtractEmptyLBBackendsEvents(out []byte) ([]emptyLBBackendEvent, error) {
	events := make([]emptyLBBackendEvent, 0, 4)

	var f Record
	err := json.Unmarshal([]byte(out), &f)
	if err != nil {
		logrus.Info("Error unmarshalling json")
		return events, err
	}
	if len(f.Data) == 0 {
		logrus.Info("No data in event")
		return events, nil
	}

	var eventInfoIndex int
	var eventTypeIndex int
	var handledIndex int
	var uuidIndex int
	for idx, val := range f.Headings {
		switch val {
		case "event_info":
			eventInfoIndex = idx
		case "event_type":
			eventTypeIndex = idx
		case "handled":
			handledIndex = idx
		case "_uuid":
			uuidIndex = idx
		}
	}

	for _, val := range f.Data {
		if val[handledIndex] == true || val[eventTypeIndex] != "empty_lb_backends" {
			logrus.Info("Event handled or not of correct type")
			continue
		}
		uuidArray, ok := val[uuidIndex].([]interface{})
		if !ok {
			logrus.Info("bad uuid parse")
			return events, errors.New("Unexpected '_uuid' data in controller event")
		}
		uuid, ok := uuidArray[1].(string)
		if !ok {
			return events, errors.New("Failed to parse UUID in controller event")
		}
		// Unpack the data. There's probably a better way to do this.
		info, ok := val[eventInfoIndex].([]interface{})
		if !ok {
			logrus.Info("bad event_info parse")
			return events, errors.New("Unexpected 'event_info' data in controller event")
		}
		eventMap, ok := info[1].([]interface{})
		if !ok {
			logrus.Info("bad event mapping parse thing")
			return events, errors.New("'event_info' data is not the expected type")
		}
		var vip string
		var protocol kapi.Protocol
		for _, x := range eventMap {
			tuple, ok := x.([]interface{})
			if !ok {
				return events, errors.New("event map item failed to parse")
			}
			switch tuple[0] {
			case "vip":
				vip, ok = tuple[1].(string)
				if (!ok) {
					return events, errors.New("Failed to parse vip in controller event")
				}
			case "protocol":
				prot, ok := tuple[1].(string)
				if (!ok) {
					return events, errors.New("Failed to parse protocol in controller event")
				}
				if prot == "udp" {
					protocol = kapi.ProtocolUDP
				} else {
					protocol = kapi.ProtocolTCP
				}
			}
		}
		logrus.Infof("Appending %s, %s, %s to events", vip, protocol, uuid)
		events = append(events, emptyLBBackendEvent{vip, protocol, uuid})
	}

	return events, nil
}

func (oc *Controller) EventChecker(stopChan chan struct{}) {
	ticker := time.NewTicker(5 * time.Second)

	util.RunOVNNbctl("set", "nb_global", ".", "options:controller_event=true")

	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartRecordingToSink(&kv1core.EventSinkImpl{Interface: oc.kube.Events()})
	recorder := eventBroadcaster.NewRecorder(scheme.Scheme, kapi.EventSource{Component: "kube-proxy"})

	for {
		select {
		case <- ticker.C:
			out, _, err := util.RunOVNSbctl("--format=json", "list", "controller_event")
			if err != nil {
				continue
			}

			events, err := ExtractEmptyLBBackendsEvents([]byte(out))
			if err != nil || len(events) == 0 {
				continue
			}

			for _, event := range(events) {
				util.RunOVNSbctl("set", "controller_event", event.uuid, "handled=true")
				if serviceName, ok := oc.GetServiceVIPToName(event.vip, event.protocol); ok {
					serviceRef := kapi.ObjectReference{
						Kind: "Service",
						Namespace: serviceName.Namespace,
						Name: serviceName.Name,
					}
					logrus.Debugf("Sending a NeedPods event for service %s in namespace %s.", serviceName.Name, serviceName.Namespace)
					recorder.Eventf(&serviceRef, kapi.EventTypeNormal, "NeedPods", "The service %s needs pods", serviceName.Name)
				}
			}
		case <- stopChan:
			return
		}
	}
}

// WatchPods starts the watching of Pod resource and calls back the appropriate handler logic
func (oc *Controller) WatchPods() error {
	_, err := oc.watchFactory.AddPodHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod := obj.(*kapi.Pod)
			if pod.Spec.NodeName != "" {
				oc.addLogicalPort(pod)
			}
		},
		UpdateFunc: func(old, newer interface{}) {
			podNew := newer.(*kapi.Pod)
			podOld := old.(*kapi.Pod)
			if podOld.Spec.NodeName == "" && podNew.Spec.NodeName != "" {
				oc.addLogicalPort(podNew)
			}
		},
		DeleteFunc: func(obj interface{}) {
			pod := obj.(*kapi.Pod)
			oc.deleteLogicalPort(pod)
		},
	}, oc.syncPods)
	return err
}

// WatchServices starts the watching of Service resource and calls back the
// appropriate handler logic
func (oc *Controller) WatchServices() error {
	_, err := oc.watchFactory.AddServiceHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) {},
		UpdateFunc: func(old, new interface{}) {},
		DeleteFunc: func(obj interface{}) {
			service := obj.(*kapi.Service)
			oc.deleteService(service)
		},
	}, oc.syncServices)
	return err
}

// WatchEndpoints starts the watching of Endpoint resource and calls back the appropriate handler logic
func (oc *Controller) WatchEndpoints() error {
	_, err := oc.watchFactory.AddEndpointsHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			ep := obj.(*kapi.Endpoints)
			err := oc.AddEndpoints(ep)
			if err != nil {
				logrus.Errorf("Error in adding load balancer: %v", err)
			}
		},
		UpdateFunc: func(old, new interface{}) {
			epNew := new.(*kapi.Endpoints)
			epOld := old.(*kapi.Endpoints)
			if reflect.DeepEqual(epNew.Subsets, epOld.Subsets) {
				return
			}
			if len(epNew.Subsets) == 0 {
				err := oc.deleteEndpoints(epNew)
				if err != nil {
					logrus.Errorf("Error in deleting endpoints - %v", err)
				}
			} else {
				err := oc.AddEndpoints(epNew)
				if err != nil {
					logrus.Errorf("Error in modifying endpoints: %v", err)
				}
			}
		},
		DeleteFunc: func(obj interface{}) {
			ep := obj.(*kapi.Endpoints)
			err := oc.deleteEndpoints(ep)
			if err != nil {
				logrus.Errorf("Error in deleting endpoints - %v", err)
			}
		},
	}, nil)
	return err
}

// WatchNetworkPolicy starts the watching of network policy resource and calls
// back the appropriate handler logic
func (oc *Controller) WatchNetworkPolicy() error {
	_, err := oc.watchFactory.AddPolicyHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			policy := obj.(*kapisnetworking.NetworkPolicy)
			oc.AddNetworkPolicy(policy)
			return
		},
		UpdateFunc: func(old, newer interface{}) {
			oldPolicy := old.(*kapisnetworking.NetworkPolicy)
			newPolicy := newer.(*kapisnetworking.NetworkPolicy)
			if !reflect.DeepEqual(oldPolicy, newPolicy) {
				oc.deleteNetworkPolicy(oldPolicy)
				oc.AddNetworkPolicy(newPolicy)
			}
			return
		},
		DeleteFunc: func(obj interface{}) {
			policy := obj.(*kapisnetworking.NetworkPolicy)
			oc.deleteNetworkPolicy(policy)
			return
		},
	}, oc.syncNetworkPolicies)
	return err
}

// WatchNamespaces starts the watching of namespace resource and calls
// back the appropriate handler logic
func (oc *Controller) WatchNamespaces() error {
	_, err := oc.watchFactory.AddNamespaceHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			ns := obj.(*kapi.Namespace)
			oc.AddNamespace(ns)
			return
		},
		UpdateFunc: func(old, newer interface{}) {
			// We only use namespace's name and that does not get updated.
			return
		},
		DeleteFunc: func(obj interface{}) {
			ns := obj.(*kapi.Namespace)
			oc.deleteNamespace(ns)
			return
		},
	}, oc.syncNamespaces)
	return err
}

// WatchNodes starts the watching of node resource and calls
// back the appropriate handler logic
func (oc *Controller) WatchNodes() error {
	_, err := oc.watchFactory.AddNodeHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) {},
		UpdateFunc: func(old, new interface{}) {},
		DeleteFunc: func(obj interface{}) {
			node := obj.(*kapi.Node)
			logrus.Debugf("Delete event for Node %q. Removing the node from "+
				"various caches", node.Name)

			oc.lsMutex.Lock()
			delete(oc.gatewayCache, node.Name)
			delete(oc.logicalSwitchCache, node.Name)
			oc.lsMutex.Unlock()
		},
	}, nil)

	return err
}

func (oc *Controller) AddServiceVIPToName(vip string, protocol kapi.Protocol, namespace, name string) {
	oc.serviceVIPToNameLock.Lock()
	defer oc.serviceVIPToNameLock.Unlock()
	oc.serviceVIPToName[ServiceVIPKey{vip, protocol}] = types.NamespacedName{namespace, name}
}

func (oc *Controller) GetServiceVIPToName(vip string, protocol kapi.Protocol) (types.NamespacedName, bool) {
	oc.serviceVIPToNameLock.Lock()
	defer oc.serviceVIPToNameLock.Unlock()
	namespace, ok := oc.serviceVIPToName[ServiceVIPKey{vip, protocol}]
	return namespace, ok
}
