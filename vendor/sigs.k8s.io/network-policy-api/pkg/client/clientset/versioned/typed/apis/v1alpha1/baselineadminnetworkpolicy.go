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

package v1alpha1

import (
	"context"
	json "encoding/json"
	"fmt"
	"time"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
	v1alpha1 "sigs.k8s.io/network-policy-api/apis/v1alpha1"
	apisv1alpha1 "sigs.k8s.io/network-policy-api/pkg/client/applyconfiguration/apis/v1alpha1"
	scheme "sigs.k8s.io/network-policy-api/pkg/client/clientset/versioned/scheme"
)

// BaselineAdminNetworkPoliciesGetter has a method to return a BaselineAdminNetworkPolicyInterface.
// A group's client should implement this interface.
type BaselineAdminNetworkPoliciesGetter interface {
	BaselineAdminNetworkPolicies() BaselineAdminNetworkPolicyInterface
}

// BaselineAdminNetworkPolicyInterface has methods to work with BaselineAdminNetworkPolicy resources.
type BaselineAdminNetworkPolicyInterface interface {
	Create(ctx context.Context, baselineAdminNetworkPolicy *v1alpha1.BaselineAdminNetworkPolicy, opts v1.CreateOptions) (*v1alpha1.BaselineAdminNetworkPolicy, error)
	Update(ctx context.Context, baselineAdminNetworkPolicy *v1alpha1.BaselineAdminNetworkPolicy, opts v1.UpdateOptions) (*v1alpha1.BaselineAdminNetworkPolicy, error)
	UpdateStatus(ctx context.Context, baselineAdminNetworkPolicy *v1alpha1.BaselineAdminNetworkPolicy, opts v1.UpdateOptions) (*v1alpha1.BaselineAdminNetworkPolicy, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha1.BaselineAdminNetworkPolicy, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha1.BaselineAdminNetworkPolicyList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.BaselineAdminNetworkPolicy, err error)
	Apply(ctx context.Context, baselineAdminNetworkPolicy *apisv1alpha1.BaselineAdminNetworkPolicyApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.BaselineAdminNetworkPolicy, err error)
	ApplyStatus(ctx context.Context, baselineAdminNetworkPolicy *apisv1alpha1.BaselineAdminNetworkPolicyApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.BaselineAdminNetworkPolicy, err error)
	BaselineAdminNetworkPolicyExpansion
}

// baselineAdminNetworkPolicies implements BaselineAdminNetworkPolicyInterface
type baselineAdminNetworkPolicies struct {
	client rest.Interface
}

// newBaselineAdminNetworkPolicies returns a BaselineAdminNetworkPolicies
func newBaselineAdminNetworkPolicies(c *PolicyV1alpha1Client) *baselineAdminNetworkPolicies {
	return &baselineAdminNetworkPolicies{
		client: c.RESTClient(),
	}
}

// Get takes name of the baselineAdminNetworkPolicy, and returns the corresponding baselineAdminNetworkPolicy object, and an error if there is any.
func (c *baselineAdminNetworkPolicies) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.BaselineAdminNetworkPolicy, err error) {
	result = &v1alpha1.BaselineAdminNetworkPolicy{}
	err = c.client.Get().
		Resource("baselineadminnetworkpolicies").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of BaselineAdminNetworkPolicies that match those selectors.
func (c *baselineAdminNetworkPolicies) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.BaselineAdminNetworkPolicyList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha1.BaselineAdminNetworkPolicyList{}
	err = c.client.Get().
		Resource("baselineadminnetworkpolicies").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested baselineAdminNetworkPolicies.
func (c *baselineAdminNetworkPolicies) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Resource("baselineadminnetworkpolicies").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a baselineAdminNetworkPolicy and creates it.  Returns the server's representation of the baselineAdminNetworkPolicy, and an error, if there is any.
func (c *baselineAdminNetworkPolicies) Create(ctx context.Context, baselineAdminNetworkPolicy *v1alpha1.BaselineAdminNetworkPolicy, opts v1.CreateOptions) (result *v1alpha1.BaselineAdminNetworkPolicy, err error) {
	result = &v1alpha1.BaselineAdminNetworkPolicy{}
	err = c.client.Post().
		Resource("baselineadminnetworkpolicies").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(baselineAdminNetworkPolicy).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a baselineAdminNetworkPolicy and updates it. Returns the server's representation of the baselineAdminNetworkPolicy, and an error, if there is any.
func (c *baselineAdminNetworkPolicies) Update(ctx context.Context, baselineAdminNetworkPolicy *v1alpha1.BaselineAdminNetworkPolicy, opts v1.UpdateOptions) (result *v1alpha1.BaselineAdminNetworkPolicy, err error) {
	result = &v1alpha1.BaselineAdminNetworkPolicy{}
	err = c.client.Put().
		Resource("baselineadminnetworkpolicies").
		Name(baselineAdminNetworkPolicy.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(baselineAdminNetworkPolicy).
		Do(ctx).
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *baselineAdminNetworkPolicies) UpdateStatus(ctx context.Context, baselineAdminNetworkPolicy *v1alpha1.BaselineAdminNetworkPolicy, opts v1.UpdateOptions) (result *v1alpha1.BaselineAdminNetworkPolicy, err error) {
	result = &v1alpha1.BaselineAdminNetworkPolicy{}
	err = c.client.Put().
		Resource("baselineadminnetworkpolicies").
		Name(baselineAdminNetworkPolicy.Name).
		SubResource("status").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(baselineAdminNetworkPolicy).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the baselineAdminNetworkPolicy and deletes it. Returns an error if one occurs.
func (c *baselineAdminNetworkPolicies) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Resource("baselineadminnetworkpolicies").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *baselineAdminNetworkPolicies) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Resource("baselineadminnetworkpolicies").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched baselineAdminNetworkPolicy.
func (c *baselineAdminNetworkPolicies) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.BaselineAdminNetworkPolicy, err error) {
	result = &v1alpha1.BaselineAdminNetworkPolicy{}
	err = c.client.Patch(pt).
		Resource("baselineadminnetworkpolicies").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}

// Apply takes the given apply declarative configuration, applies it and returns the applied baselineAdminNetworkPolicy.
func (c *baselineAdminNetworkPolicies) Apply(ctx context.Context, baselineAdminNetworkPolicy *apisv1alpha1.BaselineAdminNetworkPolicyApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.BaselineAdminNetworkPolicy, err error) {
	if baselineAdminNetworkPolicy == nil {
		return nil, fmt.Errorf("baselineAdminNetworkPolicy provided to Apply must not be nil")
	}
	patchOpts := opts.ToPatchOptions()
	data, err := json.Marshal(baselineAdminNetworkPolicy)
	if err != nil {
		return nil, err
	}
	name := baselineAdminNetworkPolicy.Name
	if name == nil {
		return nil, fmt.Errorf("baselineAdminNetworkPolicy.Name must be provided to Apply")
	}
	result = &v1alpha1.BaselineAdminNetworkPolicy{}
	err = c.client.Patch(types.ApplyPatchType).
		Resource("baselineadminnetworkpolicies").
		Name(*name).
		VersionedParams(&patchOpts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}

// ApplyStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating ApplyStatus().
func (c *baselineAdminNetworkPolicies) ApplyStatus(ctx context.Context, baselineAdminNetworkPolicy *apisv1alpha1.BaselineAdminNetworkPolicyApplyConfiguration, opts v1.ApplyOptions) (result *v1alpha1.BaselineAdminNetworkPolicy, err error) {
	if baselineAdminNetworkPolicy == nil {
		return nil, fmt.Errorf("baselineAdminNetworkPolicy provided to Apply must not be nil")
	}
	patchOpts := opts.ToPatchOptions()
	data, err := json.Marshal(baselineAdminNetworkPolicy)
	if err != nil {
		return nil, err
	}

	name := baselineAdminNetworkPolicy.Name
	if name == nil {
		return nil, fmt.Errorf("baselineAdminNetworkPolicy.Name must be provided to Apply")
	}

	result = &v1alpha1.BaselineAdminNetworkPolicy{}
	err = c.client.Patch(types.ApplyPatchType).
		Resource("baselineadminnetworkpolicies").
		Name(*name).
		SubResource("status").
		VersionedParams(&patchOpts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}
