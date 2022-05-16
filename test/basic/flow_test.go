package basic

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"path"
	"testing"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer/yaml"
	yamlutil "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/restmapper"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/envfuncs"
	"sigs.k8s.io/e2e-framework/pkg/features"
)

const (
	clusterNamePrefix = "test-cluster"
	containerName     = "localhost/ebpf-agent:test"
)

var (
	testenv env.Environment
)

var log = logrus.WithField("component", "cluster.Kind")

type ManifestDeployDefinition struct {
	Namespace    string
	PreFunction  func(ctx context.Context, cfg *envconf.Config, namespace string) error
	YamlFile     string
	PostFunction func(ctx context.Context, cfg *envconf.Config, namespace string) error
}

func TestMain(m *testing.M) {
	kindClusterName := envconf.RandomName(clusterNamePrefix, 16)

	testenv = env.New()
	testenv.Setup(
		envfuncs.CreateKindCluster(kindClusterName),
		deploy(ManifestDeployDefinition{Namespace: "default", YamlFile: path.Join("..", "base-env", "01-permissions.yml")}),
		deploy(ManifestDeployDefinition{Namespace: "default", YamlFile: path.Join("..", "base-env", "02-loki.yml")}),
		deploy(ManifestDeployDefinition{Namespace: "default", YamlFile: path.Join("..", "base-env", "03-flp.yml")}),
		func(ctx context.Context, config *envconf.Config) (context.Context, error) {
			fmt.Println("***** LOADING IMAGE INTO CLUSTER")
			//return envfuncs.LoadImageArchiveToCluster(kindClusterName, "../../cosa.tar")(ctx, config)
			return envfuncs.LoadDockerImageToCluster(kindClusterName, containerName)(ctx, config)
		},
		deploy(ManifestDeployDefinition{YamlFile: path.Join("..", "base-env", "04-agent.yml")}),
	)

	testenv.Finish(
	// TODO: retrieve all cluster logs
	//envfuncs.DestroyKindCluster(kindClusterName),
	)
	log.Info("starting kind cluster")

	code := testenv.Run(m)
	log.WithField("returnCode", code).Info("kind cluster started")
}

func TestTest(t *testing.T) {
	f1 := features.New("count pod").
		WithLabel("type", "pod-count").
		Assess("pods from kube-system", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			var pods v1.PodList
			err := cfg.Client().Resources("default").List(context.TODO(), &pods)
			if err != nil {
				t.Fatal(err)
			}
			fmt.Printf("%#v\n", pods)
			if len(pods.Items) == 0 {
				t.Fatal("no pods in namespace kube-system")
			}
			return ctx
		}).Feature()
	testenv.Test(t, f1)
}

func deploy(definition ManifestDeployDefinition) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		if definition.PreFunction != nil {
			err := definition.PreFunction(ctx, cfg, definition.Namespace)
			if err != nil {
				return ctx, fmt.Errorf("deploying PreFunction error: %w", err)
			}
		}
		if err := deployManifestFile(definition, cfg); err != nil {
			return ctx, fmt.Errorf("deploying manifest file: %w", err)
		}
		if definition.PostFunction != nil {
			if err := definition.PostFunction(ctx, cfg, definition.Namespace); err != nil {
				return ctx, fmt.Errorf("deploying PostFunction error: %w", err)
			}
		}
		return ctx, nil
	}
}

// credits to https://gist.github.com/pytimer/0ad436972a073bb37b8b6b8b474520fc
func deployManifestFile(definition ManifestDeployDefinition, cfg *envconf.Config) error {
	b, err := ioutil.ReadFile(definition.YamlFile)
	if err != nil {
		return fmt.Errorf("reading manifest file %q: %w", definition.YamlFile, err)
	}

	c, err := kubernetes.NewForConfig(cfg.Client().RESTConfig())
	if err != nil {
		return fmt.Errorf("creating kubernetes client: %w", err)
	}

	dd, err := dynamic.NewForConfig(cfg.Client().RESTConfig())
	if err != nil {
		return fmt.Errorf("creating kubernetes dynamic client: %w", err)
	}

	decoder := yamlutil.NewYAMLOrJSONDecoder(bytes.NewReader(b), 100)
	for {
		var rawObj runtime.RawExtension
		if err = decoder.Decode(&rawObj); err != nil {
			if err != io.EOF {
				return fmt.Errorf("decoding manifest raw object: %w", err)
			}
			return nil
		}

		obj, gvk, err := yaml.NewDecodingSerializer(unstructured.UnstructuredJSONScheme).Decode(rawObj.Raw, nil, nil)
		unstructuredMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
		if err != nil {
			return fmt.Errorf("deserializing object in manifest: %w", err)
		}

		unstructuredObj := &unstructured.Unstructured{Object: unstructuredMap}

		gr, err := restmapper.GetAPIGroupResources(c.Discovery())
		if err != nil {
			return fmt.Errorf("can't get API group resources: %w", err)
		}

		mapper := restmapper.NewDiscoveryRESTMapper(gr)
		mapping, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
		if err != nil {
			return fmt.Errorf("creating REST Mapping: %w", err)
		}

		var dri dynamic.ResourceInterface
		if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
			if unstructuredObj.GetNamespace() == "" {
				unstructuredObj.SetNamespace("default")
			}
			dri = dd.Resource(mapping.Resource).Namespace(unstructuredObj.GetNamespace())
		} else {
			dri = dd.Resource(mapping.Resource)
		}

		if _, err := dri.Create(context.Background(), unstructuredObj, metav1.CreateOptions{}); err != nil {
			log.Fatal(err)
		}
	}
}
