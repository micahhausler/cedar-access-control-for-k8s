/*
Copyright 2024.

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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	StrictValidationMode     = "strict"
	PermissiveValidationMode = "permissive"
)

// PolicyValidation defines the
type PolicyValidation struct {
	// Enforced indicates if creation or updates to the policy require schema validation
	//+required
	//+kubebuilder:default:value=false
	Enforced bool `json:"enforced"`

	// ValidationMode indicates which validation mode to use.
	// A value of `strict` requires that only literals are passed to extension functions (IP, decimal, datetime), and not entity attributes.
	// See https://docs.cedarpolicy.com/policies/validation.html#validation-benefits-of-schema for more details.
	//+kubebuilder:validation:Enum=strict;permissive
	//+default:value=strict
	//+optional
	ValidationMode string `json:"validationMode"`
}

// PolicySpec defines the desired state of Policy
type PolicySpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// Content is a string representing the policy content
	//+required
	Content string `json:"content"`

	// Validation
	//+required
	Validation PolicyValidation `json:"validation"`
}

// PolicyStatus defines the observed state of Policy
type PolicyStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:scope=Cluster

// Policy is the Schema for the policies API
type Policy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	//+required
	Spec   PolicySpec   `json:"spec"`
	Status PolicyStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// PolicyList contains a list of Policy
type PolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Policy `json:"items"`
}

// E2ELatencyLog represents the log structure to emit when calculating e2e latency
type E2ELatencyLog struct {
	ClusterID string  `json:"ClusterId"`
	Version   string  `json:"Version"`
	Type      string  `json:"Type"`
	Latency   float64 `json:"Latency"`
}
