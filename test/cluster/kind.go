package cluster

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"path"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
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
)

const (
	agentContainerName = "localhost/ebpf-agent:test"
	namespace          = "default"
	timeout            = 60 * time.Second
)

var log = logrus.WithField("component", "cluster.Kind")

var defaultBaseDeployments = []ManifestDeployDefinition{
	{YamlFile: path.Join("cluster", "base", "01-permissions.yml")},
	{YamlFile: path.Join("cluster", "base", "02-loki.yml"),
		ReadyFunction: (&Loki{BaseURL: "http://127.0.0.1:30100"}).Ready},
	{YamlFile: path.Join("cluster", "base", "03-flp.yml")},
	{YamlFile: path.Join("cluster", "base", "04-agent.yml")},
}

type ManifestDeployDefinition struct {
	// YamlFile relative location from the `${project.root}/test` folder
	YamlFile      string
	ReadyFunction func() error
}

type Kind struct {
	clusterName    string
	baseComponents []ManifestDeployDefinition
	testEnv        env.Environment
}

// TODO: enable options to override baseComponents, cleanups, etc...
func NewKind(kindClusterName string) *Kind {
	return &Kind{
		testEnv:        env.New(),
		clusterName:    kindClusterName,
		baseComponents: defaultBaseDeployments,
	}
}

func (k *Kind) Run(m *testing.M) {
	envFuncs := []env.Func{
		envfuncs.CreateKindClusterWithConfig(k.clusterName,
			"kindest/node:v1.24.0",
			path.Join("..", "cluster", "base", "00-kind.yml")),
		envfuncs.LoadDockerImageToCluster(k.clusterName, agentContainerName),
	}
	// Deploy component dependencies: loki, flp,
	for _, c := range k.baseComponents {
		envFuncs = append(envFuncs, deploy(c))
	}
	//// Execute port-forward, if defined
	//for _, c := range k.baseComponents {
	//	envFuncs = append(envFuncs, withTimeout(portForward(c)))
	//}
	// Execute readyness functions, if defined
	for _, c := range k.baseComponents {
		envFuncs = append(envFuncs, withTimeout(isReady(c)))
	}

	log.Info("starting tests")
	code := k.testEnv.Setup(envFuncs...).
		Finish(
		// TODO: retrieve all cluster logs
		//envfuncs.DestroyKindCluster(kindClusterName),
		).Run(m)
	log.WithField("returnCode", code).Info("tests finished run")
}

func (k *Kind) TestEnv() env.Environment {
	return k.testEnv
}

func deploy(definition ManifestDeployDefinition) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		kclient, err := kubernetes.NewForConfig(cfg.Client().RESTConfig())
		if err != nil {
			return ctx, fmt.Errorf("creating kubernetes client: %w", err)
		}
		if err := deployManifestFile(definition, cfg, kclient); err != nil {
			return ctx, fmt.Errorf("deploying manifest file: %w", err)
		}
		return ctx, nil
	}
}

// credits to https://gist.github.com/pytimer/0ad436972a073bb37b8b6b8b474520fc
func deployManifestFile(definition ManifestDeployDefinition,
	cfg *envconf.Config,
	kclient *kubernetes.Clientset,
) error {
	b, err := ioutil.ReadFile(path.Join("..", definition.YamlFile))
	if err != nil {
		return fmt.Errorf("reading manifest file %q: %w", definition.YamlFile, err)
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

		gr, err := restmapper.GetAPIGroupResources(kclient.Discovery())
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
				unstructuredObj.SetNamespace(namespace)
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

func withTimeout(f env.Func) env.Func {
	tlog := log.WithField("function", "withTimeout")
	return func(ctx context.Context, config *envconf.Config) (context.Context, error) {
		start := time.Now()
		for {
			ctx, err := f(ctx, config)
			if err == nil {
				return ctx, nil
			}
			if time.Now().Sub(start) > timeout {
				return ctx, fmt.Errorf("timeout (%s) trying to execute function: %w", timeout, err)
			}
			tlog.WithError(err).Debug("function did not succeed. Retrying after 1s")
			time.Sleep(time.Second)
		}
	}
}

func isReady(definition ManifestDeployDefinition) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		if definition.ReadyFunction != nil {
			log.WithFields(logrus.Fields{
				"function":   "isReady",
				"deployment": definition.YamlFile,
			}).Debug("checking readiness")
			if err := definition.ReadyFunction(); err != nil {
				return ctx, fmt.Errorf("component not ready: %w", err)
			}
		}
		return ctx, nil
	}
}
