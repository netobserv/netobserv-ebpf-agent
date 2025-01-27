// Copyright 2024 VMware, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package collector

import (
	"bytes"
	"fmt"
	"sync"
	"time"

	"k8s.io/klog/v2"

	"github.com/vmware/go-ipfix/pkg/entities"
)

type transportSession struct {
	protocol string
	id       string
	mutex    sync.RWMutex
	// for each obsDomainID, there is a map of templates (indexed by templateID)
	templatesMap map[uint32]map[uint16]*template

	// these fields are used for UDP packet handling
	packetChan       chan *bytes.Buffer
	closeSessionChan chan struct{}
}

func newUDPSession(id string) *transportSession {
	return &transportSession{
		protocol:         "udp",
		id:               id,
		templatesMap:     make(map[uint32]map[uint16]*template),
		packetChan:       make(chan *bytes.Buffer),
		closeSessionChan: make(chan struct{}),
	}
}

func newTCPSession(id string) *transportSession {
	return &transportSession{
		protocol:     "tcp",
		id:           id,
		templatesMap: make(map[uint32]map[uint16]*template),
	}
}

func (s *transportSession) addTemplate(clock clock, obsDomainID uint32, templateID uint16, elementsWithValue []entities.InfoElementWithValue, templateTTL time.Duration) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if _, ok := s.templatesMap[obsDomainID]; !ok {
		s.templatesMap[obsDomainID] = make(map[uint16]*template)
	}
	elements := make([]*entities.InfoElement, 0)
	for _, elementWithValue := range elementsWithValue {
		elements = append(elements, elementWithValue.GetInfoElement())
	}
	tpl, ok := s.templatesMap[obsDomainID][templateID]
	if !ok {
		tpl = &template{}
		s.templatesMap[obsDomainID][templateID] = tpl
	}
	tpl.ies = elements
	klog.V(4).InfoS("Added template to template map", "obsDomainID", obsDomainID, "templateID", templateID)
	// Template lifetime management for UDP.
	if s.protocol != "udp" {
		return
	}
	tpl.expiryTime = clock.Now().Add(templateTTL)
	if tpl.expiryTimer == nil {
		tpl.expiryTimer = clock.AfterFunc(templateTTL, func() {
			klog.Infof("Template with id %d, and obsDomainID %d is expired.", templateID, obsDomainID)
			now := clock.Now()
			// From the Go documentation:
			//   For a func-based timer created with AfterFunc(d, f), Reset either
			//   reschedules when f will run, in which case Reset returns true, or
			//   schedules f to run again, in which case it returns false. When Reset
			//   returns false, Reset neither waits for the prior f to complete before
			//   returning nor does it guarantee that the subsequent goroutine running f
			//   does not run concurrently with the prior one. If the caller needs to
			//   know whether the prior execution of f is completed, it must coordinate
			//   with f explicitly.
			// In our case, when f executes, we have to verify that the record is indeed
			// scheduled for deletion by checking expiryTime. We cannot just
			// automatically delete the template.
			s.deleteTemplateWithConds(obsDomainID, templateID, func(tpl *template) bool {
				// lock will be held when this executes
				return !tpl.expiryTime.After(now)
			})
		})
	} else {
		tpl.expiryTimer.Reset(templateTTL)
	}
}

// deleteTemplate returns true iff a template was actually deleted.
func (s *transportSession) deleteTemplate(obsDomainID uint32, templateID uint16) bool {
	return s.deleteTemplateWithConds(obsDomainID, templateID)
}

// deleteTemplateWithConds returns true iff a template was actually deleted.
func (s *transportSession) deleteTemplateWithConds(obsDomainID uint32, templateID uint16, condFns ...func(*template) bool) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	template, ok := s.templatesMap[obsDomainID][templateID]
	if !ok {
		return false
	}
	for _, condFn := range condFns {
		if !condFn(template) {
			return false
		}
	}
	// expiryTimer will be nil when the protocol is TS.
	if template.expiryTimer != nil {
		// expiryTimer may have been stopped already (if the timer
		// expired and is the reason why the template is being deleted),
		// but it is safe to call Stop() on an expired timer.
		template.expiryTimer.Stop()
	}
	delete(s.templatesMap[obsDomainID], templateID)
	klog.V(4).InfoS("Deleted template from template map", "obsDomainID", obsDomainID, "templateID", templateID)
	if len(s.templatesMap[obsDomainID]) == 0 {
		delete(s.templatesMap, obsDomainID)
		klog.V(4).InfoS("No more templates for observation domain", "obsDomainID", obsDomainID)
	}
	return true
}

func (s *transportSession) getTemplateIEs(obsDomainID uint32, templateID uint16) ([]*entities.InfoElement, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	if template, ok := s.templatesMap[obsDomainID][templateID]; ok {
		return template.ies, nil
	} else {
		return nil, fmt.Errorf("template %d with obsDomainID %d does not exist", templateID, obsDomainID)
	}
}
