//
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

// Code generated by lister-gen. DO NOT EDIT.

package v1

import (
	v1 "github.com/haproxytech/kubernetes-ingress/crs/api/ingress/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// TCPLister helps list TCPs.
// All objects returned here must be treated as read-only.
type TCPLister interface {
	// List lists all TCPs in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1.TCP, err error)
	// TCPs returns an object that can list and get TCPs.
	TCPs(namespace string) TCPNamespaceLister
	TCPListerExpansion
}

// tCPLister implements the TCPLister interface.
type tCPLister struct {
	indexer cache.Indexer
}

// NewTCPLister returns a new TCPLister.
func NewTCPLister(indexer cache.Indexer) TCPLister {
	return &tCPLister{indexer: indexer}
}

// List lists all TCPs in the indexer.
func (s *tCPLister) List(selector labels.Selector) (ret []*v1.TCP, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1.TCP))
	})
	return ret, err
}

// TCPs returns an object that can list and get TCPs.
func (s *tCPLister) TCPs(namespace string) TCPNamespaceLister {
	return tCPNamespaceLister{indexer: s.indexer, namespace: namespace}
}

// TCPNamespaceLister helps list and get TCPs.
// All objects returned here must be treated as read-only.
type TCPNamespaceLister interface {
	// List lists all TCPs in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1.TCP, err error)
	// Get retrieves the TCP from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1.TCP, error)
	TCPNamespaceListerExpansion
}

// tCPNamespaceLister implements the TCPNamespaceLister
// interface.
type tCPNamespaceLister struct {
	indexer   cache.Indexer
	namespace string
}

// List lists all TCPs in the indexer for a given namespace.
func (s tCPNamespaceLister) List(selector labels.Selector) (ret []*v1.TCP, err error) {
	err = cache.ListAllByNamespace(s.indexer, s.namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v1.TCP))
	})
	return ret, err
}

// Get retrieves the TCP from the indexer for a given namespace and name.
func (s tCPNamespaceLister) Get(name string) (*v1.TCP, error) {
	obj, exists, err := s.indexer.GetByKey(s.namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1.Resource("tcp"), name)
	}
	return obj.(*v1.TCP), nil
}
