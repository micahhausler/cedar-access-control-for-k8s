package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/awslabs/cedar-access-control-for-k8s/internal/convert"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/klog/v2"
	"sigs.k8s.io/yaml"
)

func main() {
	input := flag.String("input", "", "File name to read in. If empty, read from a cluster")
	format := flag.String("output", "cedar", "Output format. One of [cedar, json]")
	// namespace := flag.String("namespace", "default", "Namespace to query when getting a single rolebinding")
	klog.InitFlags(flag.CommandLine)
	flag.Parse()
	defer klog.Flush()

	data, err := os.ReadFile(*input)
	if err != nil {
		panic(err)
	}
	vap := &admissionregistrationv1.ValidatingAdmissionPolicy{}
	err = yaml.Unmarshal(data, vap)
	if err != nil {
		panic(err)
	}

	ps, err := convert.VapToCedar(vap)
	if err != nil {
		panic(err)
	}
	switch *format {
	case "json":
		data, _ := ps.MarshalJSON()
		fmt.Println(string(data))
	case "cedar":
		fmt.Println(string(ps.MarshalCedar()))
	default:
		klog.Fatalf("Invalid output format: %s", *format)
	}
}
