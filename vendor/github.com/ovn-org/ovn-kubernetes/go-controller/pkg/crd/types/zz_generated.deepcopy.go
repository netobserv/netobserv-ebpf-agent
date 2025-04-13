//go:build !ignore_autogenerated
// +build !ignore_autogenerated

/*


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
// Code generated by deepcopy-gen. DO NOT EDIT.

package types

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ClusterUserDefinedNetworkSelector) DeepCopyInto(out *ClusterUserDefinedNetworkSelector) {
	*out = *in
	in.NetworkSelector.DeepCopyInto(&out.NetworkSelector)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ClusterUserDefinedNetworkSelector.
func (in *ClusterUserDefinedNetworkSelector) DeepCopy() *ClusterUserDefinedNetworkSelector {
	if in == nil {
		return nil
	}
	out := new(ClusterUserDefinedNetworkSelector)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NetworkAttachmentDefinitionSelector) DeepCopyInto(out *NetworkAttachmentDefinitionSelector) {
	*out = *in
	in.NamespaceSelector.DeepCopyInto(&out.NamespaceSelector)
	in.NetworkSelector.DeepCopyInto(&out.NetworkSelector)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NetworkAttachmentDefinitionSelector.
func (in *NetworkAttachmentDefinitionSelector) DeepCopy() *NetworkAttachmentDefinitionSelector {
	if in == nil {
		return nil
	}
	out := new(NetworkAttachmentDefinitionSelector)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NetworkSelector) DeepCopyInto(out *NetworkSelector) {
	*out = *in
	if in.ClusterUserDefinedNetworkSelector != nil {
		in, out := &in.ClusterUserDefinedNetworkSelector, &out.ClusterUserDefinedNetworkSelector
		*out = new(ClusterUserDefinedNetworkSelector)
		(*in).DeepCopyInto(*out)
	}
	if in.PrimaryUserDefinedNetworkSelector != nil {
		in, out := &in.PrimaryUserDefinedNetworkSelector, &out.PrimaryUserDefinedNetworkSelector
		*out = new(PrimaryUserDefinedNetworkSelector)
		(*in).DeepCopyInto(*out)
	}
	if in.SecondaryUserDefinedNetworkSelector != nil {
		in, out := &in.SecondaryUserDefinedNetworkSelector, &out.SecondaryUserDefinedNetworkSelector
		*out = new(SecondaryUserDefinedNetworkSelector)
		(*in).DeepCopyInto(*out)
	}
	if in.NetworkAttachmentDefinitionSelector != nil {
		in, out := &in.NetworkAttachmentDefinitionSelector, &out.NetworkAttachmentDefinitionSelector
		*out = new(NetworkAttachmentDefinitionSelector)
		(*in).DeepCopyInto(*out)
	}
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NetworkSelector.
func (in *NetworkSelector) DeepCopy() *NetworkSelector {
	if in == nil {
		return nil
	}
	out := new(NetworkSelector)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in NetworkSelectors) DeepCopyInto(out *NetworkSelectors) {
	{
		in := &in
		*out = make(NetworkSelectors, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
		return
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NetworkSelectors.
func (in NetworkSelectors) DeepCopy() NetworkSelectors {
	if in == nil {
		return nil
	}
	out := new(NetworkSelectors)
	in.DeepCopyInto(out)
	return *out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PrimaryUserDefinedNetworkSelector) DeepCopyInto(out *PrimaryUserDefinedNetworkSelector) {
	*out = *in
	in.NamespaceSelector.DeepCopyInto(&out.NamespaceSelector)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PrimaryUserDefinedNetworkSelector.
func (in *PrimaryUserDefinedNetworkSelector) DeepCopy() *PrimaryUserDefinedNetworkSelector {
	if in == nil {
		return nil
	}
	out := new(PrimaryUserDefinedNetworkSelector)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *SecondaryUserDefinedNetworkSelector) DeepCopyInto(out *SecondaryUserDefinedNetworkSelector) {
	*out = *in
	in.NamespaceSelector.DeepCopyInto(&out.NamespaceSelector)
	in.NetworkSelector.DeepCopyInto(&out.NetworkSelector)
	return
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new SecondaryUserDefinedNetworkSelector.
func (in *SecondaryUserDefinedNetworkSelector) DeepCopy() *SecondaryUserDefinedNetworkSelector {
	if in == nil {
		return nil
	}
	out := new(SecondaryUserDefinedNetworkSelector)
	in.DeepCopyInto(out)
	return out
}
