// Copyright 2019 HAProxy Technologies LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package k8s

import (
	"context"
	"strings"
	"time"

	k8ssync "github.com/haproxytech/kubernetes-ingress/pkg/k8s/sync"
	"github.com/haproxytech/kubernetes-ingress/pkg/utils"
	"k8s.io/client-go/tools/cache"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	crdclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apiextensionsinformers "k8s.io/apiextensions-apiserver/pkg/client/informers/externalversions"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type groupKindEvent string

const (
	groupKindAdded   groupKindEvent = "added"
	groupKindDeleted groupKindEvent = "deleted"
)

type GroupKind struct {
	Group string
	Kind  string
	Event groupKindEvent
}

func (k k8s) runCRDefinitionsInformer(eventChan chan GroupKind, stop chan struct{}) { //nolint:ireturn
	// Create a new informer factory with the clientset.

	factory := apiextensionsinformers.NewSharedInformerFactoryWithOptions(k.apiExtensionsClient, k.cacheResyncPeriod)
	informer := factory.Apiextensions().V1().CustomResourceDefinitions().Informer()
	errW := informer.SetWatchErrorHandler(func(r *cache.Reflector, err error) {
		go logger.Debug("CRD Definitions informer error: %s", err)
	})
	logger.Error(errW)
	_, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			crd, ok := obj.(*apiextensionsv1.CustomResourceDefinition)
			if !ok {
				return
			}
			groupKind, ok := groupKindIfVersionServed(crd)
			if !ok {
				return
			}
			if k.hasActiveCRInformer(groupKind.Group, groupKind.Kind) {
				return
			}
			groupKind.Event = groupKindAdded
			scheduleGroupKindEvent(eventChan, groupKind, k.apiExtensionsClient)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			crd, ok := newObj.(*apiextensionsv1.CustomResourceDefinition)
			if !ok {
				return
			}
			if groupKind, ok := groupKindIfVersionServed(crd); ok {
				if k.hasActiveCRInformer(groupKind.Group, groupKind.Kind) {
					return
				}
				groupKind.Event = groupKindAdded
				scheduleGroupKindEvent(eventChan, groupKind, k.apiExtensionsClient)
				return
			}
			oldCRD, ok := oldObj.(*apiextensionsv1.CustomResourceDefinition)
			if !ok {
				oldCRD = extractCRD(oldObj)
			}
			groupKind, ok := groupKindIfSupported(oldCRD)
			if !ok {
				return
			}
			if !k.hasActiveCRInformer(groupKind.Group, groupKind.Kind) {
				return
			}
			groupKind.Event = groupKindDeleted
			scheduleGroupKindEvent(eventChan, groupKind, k.apiExtensionsClient)
		},
		DeleteFunc: func(obj interface{}) {
			crd := extractCRD(obj)
			groupKind, ok := groupKindIfSupported(crd)
			if !ok {
				return
			}
			if !k.hasActiveCRInformer(groupKind.Group, groupKind.Kind) {
				return
			}
			groupKind.Event = groupKindDeleted
			scheduleGroupKindEvent(eventChan, groupKind, k.apiExtensionsClient)
		},
	})

	go informer.Run(stop)

	if !cache.WaitForCacheSync(stop, informer.HasSynced) {
		logger.Error("Caches are not populated due to an underlying error, cannot monitor CRS creation")
	}

	logger.Error(err)
}

//revive:disable-next-line:cognitive-complexity
func (k k8s) RunCRSCreationMonitoring(eventChan chan k8ssync.SyncDataEvent, stop chan struct{}, osArgs utils.OSArgs) {
	eventCRS := make(chan GroupKind)
	k.runCRDefinitionsInformer(eventCRS, stop)
	go func(chan GroupKind) {
		for {
			select {
			case groupKind := <-eventCRS:
				switch groupKind.Event {
				case groupKindAdded:
					if k.hasActiveCRInformer(groupKind.Group, groupKind.Kind) {
						continue
					}
					informersSyncedEvent := &[]cache.InformerSynced{}
					for _, namespace := range k.whiteListedNS {
						crsV1 := map[string]CRV1{}
						crsV3 := map[string]CRV3{}
						switch groupKind.Group {
						case "ingress.v1.haproxy.org":
							switch groupKind.Kind {
							case "Backend":
								crsV1[groupKind.Kind] = NewBackendCRV1()
							case "Defaults":
								crsV1[groupKind.Kind] = NewDefaultsCRV1()
							case "Global":
								crsV1[groupKind.Kind] = NewGlobalCRV1()
							case "TCP":
								crsV1[groupKind.Kind] = NewTCPCRV1()
							}
							if cr, ok := crsV1[groupKind.Kind]; ok {
								k.crsV1["ingress.v1.haproxy.org - "+groupKind.Kind] = cr
								logger.Info("Custom resource definition created, adding CR watcher for " + cr.GetKind())
							}
						case "ingress.v3.haproxy.org":
							switch groupKind.Kind {
							case "Backend":
								crsV3[groupKind.Kind] = NewBackendCRV3()
							case "Defaults":
								crsV3[groupKind.Kind] = NewDefaultsCRV3()
							case "Global":
								crsV3[groupKind.Kind] = NewGlobalCRV3()
							case "TCP":
								crsV3[groupKind.Kind] = NewTCPCRV3()
							case "ValidationRules":
								if osArgs.CustomValidationRules.Name != "" {
									crsV3[groupKind.Kind] = NewValidationCRV3()
								}
							case "Frontend":
								crsV3[groupKind.Kind] = NewFrontendCRV3()
							}
							if cr, ok := crsV3[groupKind.Kind]; ok {
								k.crsV3["ingress.v3.haproxy.org - "+groupKind.Kind] = cr
								logger.Info("Custom resource definition created, adding CR watcher for " + cr.GetKind() + " " + groupKind.Group)
							}
						}

						if len(crsV1) == 0 && len(crsV3) == 0 {
							continue
						}

						k.runCRInformers(eventChan, stop, namespace, informersSyncedEvent, crsV1, crsV3, osArgs)
					}

					if len(*informersSyncedEvent) == 0 {
						continue
					}

					if !cache.WaitForCacheSync(stop, *informersSyncedEvent...) {
						logger.Error("Caches are not populated due to an underlying error, cannot monitor new CRDs")
					}
				case groupKindDeleted:
					k.stopCRInformers(groupKind.Group, groupKind.Kind)
				}
			case <-stop:
				return
			}
		}
	}(eventCRS)
}

func scheduleGroupKindEvent(eventChan chan GroupKind, groupKind GroupKind, apiExtClient *crdclientset.Clientset) {
	if groupKind.Event == groupKindAdded {
		waitForCRDEstablished(apiExtClient, groupKind)
	}
	eventChan <- groupKind
}

// waitForCRDEstablished polls the CRD status conditions until the CRD is established
// (i.e., the API server is ready to serve its resources), with a timeout.
func waitForCRDEstablished(clientset *crdclientset.Clientset, groupKind GroupKind) {
	crdName := crdPluralName(groupKind.Kind) + "." + groupKind.Group

	timeout := time.After(30 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			logger.Warningf("Timed out waiting for CRD %s to become established", crdName)
			return
		case <-ticker.C:
			crd, err := clientset.ApiextensionsV1().CustomResourceDefinitions().Get(
				context.Background(), crdName, metav1.GetOptions{})
			if err != nil {
				continue
			}
			for _, condition := range crd.Status.Conditions {
				if condition.Type == apiextensionsv1.Established &&
					condition.Status == apiextensionsv1.ConditionTrue {
					logger.Infof("CRD %s is established", crdName)
					return
				}
			}
		}
	}
}

// crdPluralName returns the lowercase plural resource name for a CRD Kind.
func crdPluralName(kind string) string {
	// These kinds already use their canonical plural in CRD naming
	knownPlurals := map[string]string{
		"Backend":         "backends",
		"Defaults":        "defaults",
		"Global":          "globals",
		"TCP":             "tcps",
		"Frontend":        "frontends",
		"ValidationRules": "validationrules",
	}
	if plural, ok := knownPlurals[kind]; ok {
		return plural
	}
	return strings.ToLower(kind) + "s"
}

func groupKindIfSupported(crd *apiextensionsv1.CustomResourceDefinition) (GroupKind, bool) {
	if crd == nil {
		return GroupKind{}, false
	}
	if !(crd.Spec.Names.Kind == "Global" ||
		crd.Spec.Names.Kind == "Defaults" ||
		crd.Spec.Names.Kind == "Backend" ||
		crd.Spec.Names.Kind == "TCP" ||
		crd.Spec.Names.Kind == "Frontend" ||
		crd.Spec.Names.Kind == "ValidationRules") {
		return GroupKind{}, false
	}
	if crd.Spec.Group != "ingress.v1.haproxy.org" && crd.Spec.Group != "ingress.v3.haproxy.org" {
		return GroupKind{}, false
	}
	switch crd.Spec.Names.Kind {
	case "Backend", "Defaults", "Global", "TCP", "Frontend", "ValidationRules":
		return GroupKind{Group: crd.Spec.Group, Kind: crd.Spec.Names.Kind}, true
	default:
		return GroupKind{}, false
	}
}

func groupKindIfVersionServed(crd *apiextensionsv1.CustomResourceDefinition) (GroupKind, bool) {
	groupKind, ok := groupKindIfSupported(crd)
	if !ok {
		return GroupKind{}, false
	}
	versionName := "v1"
	if groupKind.Group == "ingress.v3.haproxy.org" {
		versionName = "v3"
	}
	for _, version := range crd.Spec.Versions {
		if version.Name == versionName && version.Served {
			return groupKind, true
		}
	}
	return GroupKind{}, false
}

func extractCRD(obj interface{}) *apiextensionsv1.CustomResourceDefinition {
	crd, ok := obj.(*apiextensionsv1.CustomResourceDefinition)
	if ok {
		return crd
	}
	tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
	if !ok {
		return nil
	}
	crd, ok = tombstone.Obj.(*apiextensionsv1.CustomResourceDefinition)
	if !ok {
		return nil
	}
	return crd
}

func (k k8s) hasActiveCRInformer(group, kind string) bool {
	key := crInformerKey(group, kind)
	k.crInformerCancelsMu.Lock()
	cancels := k.crInformerCancels[key]
	k.crInformerCancelsMu.Unlock()
	return len(cancels) > 0
}

func (k k8s) registerCRInformerCancel(group, kind string, cancel context.CancelFunc) {
	key := crInformerKey(group, kind)
	k.crInformerCancelsMu.Lock()
	k.crInformerCancels[key] = append(k.crInformerCancels[key], cancel)
	k.crInformerCancelsMu.Unlock()
}

func (k k8s) stopCRInformers(group, kind string) {
	key := crInformerKey(group, kind)
	k.crInformerCancelsMu.Lock()
	cancels := k.crInformerCancels[key]
	delete(k.crInformerCancels, key)
	k.crInformerCancelsMu.Unlock()

	if len(cancels) == 0 {
		return
	}

	logger.Infof("Custom resource definition removed, stopping CR watcher for %s/%s", group, kind)
	for _, cancel := range cancels {
		cancel()
	}

	mapKey := group + " - " + kind
	switch group {
	case "ingress.v1.haproxy.org":
		delete(k.crsV1, mapKey)
	case "ingress.v3.haproxy.org":
		delete(k.crsV3, mapKey)
	}
}

func crInformerKey(group, kind string) string {
	return group + "/" + kind
}
