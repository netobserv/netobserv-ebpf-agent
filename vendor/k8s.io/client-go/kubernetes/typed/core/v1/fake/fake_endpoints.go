/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	v1 "k8s.io/api/core/v1"
	corev1 "k8s.io/client-go/applyconfigurations/core/v1"
	gentype "k8s.io/client-go/gentype"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
)

// fakeEndpoints implements EndpointsInterface
type fakeEndpoints struct {
	*gentype.FakeClientWithListAndApply[*v1.Endpoints, *v1.EndpointsList, *corev1.EndpointsApplyConfiguration]
	Fake *FakeCoreV1
}

func newFakeEndpoints(fake *FakeCoreV1, namespace string) typedcorev1.EndpointsInterface {
	return &fakeEndpoints{
		gentype.NewFakeClientWithListAndApply[*v1.Endpoints, *v1.EndpointsList, *corev1.EndpointsApplyConfiguration](
			fake.Fake,
			namespace,
			v1.SchemeGroupVersion.WithResource("endpoints"),
			v1.SchemeGroupVersion.WithKind("Endpoints"),
			func() *v1.Endpoints { return &v1.Endpoints{} },
			func() *v1.EndpointsList { return &v1.EndpointsList{} },
			func(dst, src *v1.EndpointsList) { dst.ListMeta = src.ListMeta },
			func(list *v1.EndpointsList) []*v1.Endpoints { return gentype.ToPointerSlice(list.Items) },
			func(list *v1.EndpointsList, items []*v1.Endpoints) { list.Items = gentype.FromPointerSlice(items) },
		),
		fake,
	}
}
