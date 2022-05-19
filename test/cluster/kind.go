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

	rt2 "runtime"

	"github.com/netobserv/netobserv-ebpf-agent/test/cluster/tester"
	"github.com/sirupsen/logrus"
	"github.com/vladimirvivien/gexe"
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
	kindImage          = "kindest/node:v1.24.0"
	namespace          = "default"
	timeout            = 120 * time.Second
)

var log = logrus.WithField("component", "cluster.Kind")

var defaultBaseDeployments = []Deployment{
	{ManifestFile: path.Join(packageDir(), "base", "01-permissions.yml")},
	{ManifestFile: path.Join(packageDir(), "base", "02-loki.yml"),
		ReadyFunction: (&tester.Loki{BaseURL: "http://127.0.0.1:30100"}).Ready},
	{ManifestFile: path.Join(packageDir(), "base", "03-flp.yml")},
	{ManifestFile: path.Join(packageDir(), "base", "04-agent.yml")},
}

// Deployment of components. Not only K8s deployments but also Pods, Services, DaemonSets, ...
type Deployment struct {
	// ManifestFile path to the kubectl-like YAML manifest file
	ManifestFile  string
	ReadyFunction func() error
}

type Kind struct {
	clusterName     string
	deployManifests []Deployment
	testEnv         env.Environment
}

type Option func(k *Kind)

func AddDeployments(defs ...Deployment) Option {
	return func(k *Kind) {
		k.deployManifests = append(k.deployManifests, defs...)
	}
}

// TODO: enable options to override deployManifests, cleanups, etc...
func NewKind(kindClusterName string, options ...Option) *Kind {
	k := &Kind{
		testEnv:         env.New(),
		clusterName:     kindClusterName,
		deployManifests: defaultBaseDeployments,
	}
	for _, option := range options {
		option(k)
	}
	return k
}

func (k *Kind) Run(m *testing.M) {
	envFuncs := []env.Func{
		envfuncs.CreateKindClusterWithConfig(k.clusterName,
			kindImage,
			path.Join(packageDir(), "base", "00-kind.yml")),
		envfuncs.LoadDockerImageToCluster(k.clusterName, agentContainerName),
	}
	// Deploy base cluster dependencies
	for _, c := range k.deployManifests {
		envFuncs = append(envFuncs, deploy(c))
	}
	// Wait for components' readiness
	for _, c := range k.deployManifests {
		envFuncs = append(envFuncs, withTimeout(isReady(c)))
	}

	log.Info("starting kind setup")
	code := k.testEnv.Setup(envFuncs...).
		Finish(
			exportLogs(k.clusterName),
			// TODO: retrieve all cluster logs
			envfuncs.DestroyKindCluster(k.clusterName),
		).Run(m)
	log.WithField("returnCode", code).Info("tests finished run")
}

func exportLogs(name string) env.Func {
	return func(ctx context.Context, config *envconf.Config) (context.Context, error) {
		log.Info("exporting cluster logs")
		exe := gexe.New()
		out := exe.Run("kind export logs ./test-logs --name " + name)
		log.WithField("out", out).Debug("exported cluster logs")
		return ctx, nil
	}
}

func (k *Kind) TestEnv() env.Environment {
	return k.testEnv
}

func deploy(definition Deployment) env.Func {
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
func deployManifestFile(definition Deployment,
	cfg *envconf.Config,
	kclient *kubernetes.Clientset,
) error {
	b, err := ioutil.ReadFile(definition.ManifestFile)
	if err != nil {
		return fmt.Errorf("reading manifest file %q: %w", definition.ManifestFile, err)
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

func isReady(definition Deployment) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		if definition.ReadyFunction != nil {
			log.WithFields(logrus.Fields{
				"function":   "isReady",
				"deployment": definition.ManifestFile,
			}).Debug("checking readiness")
			if err := definition.ReadyFunction(); err != nil {
				return ctx, fmt.Errorf("component not ready: %w", err)
			}
		}
		return ctx, nil
	}
}

// helper to get the base directory of this package, allowing to load the test deployment
// files whatever the working directory is
func packageDir() string {
	_, file, _, ok := rt2.Caller(1)
	if !ok {
		panic("can't find package directory for (project_dir)/test/cluster")
	}
	return path.Dir(file)
}
