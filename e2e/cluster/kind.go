// Package cluster cointains the base setup for the test environment. This is:
// - Deployment manifests for a base cluster: Loki, permissions, flowlogs-processor and the
//   local version of the agent. As well as the cluster configuration for ports exposure.
// - Utility classes to programmatically manage the Kind cluster and some of its components
//   (e.g. Loki)
package cluster

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"path"
	"testing"
	"time"

	rt2 "runtime"

	"github.com/netobserv/netobserv-ebpf-agent/e2e/cluster/tester"
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
	logsSubDir         = "e2e-logs"
	localArchiveName   = "ebpf-agent.tar"
)

var log = logrus.WithField("component", "cluster.Kind")

// defaultBaseDeployments are a list of components that are common to any test environment
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

// Kind cluster deployed by each TestMain function, prepared for a given test scenario.
type Kind struct {
	clusterName     string
	baseDir         string
	deployManifests []Deployment
	testEnv         env.Environment
}

// Option that can be passed to the NewKind function in order to change the configuration
// of the test cluster
// TODO: enable options to override deployManifests, cleanups, etc...
type Option func(k *Kind)

// AddDeployments can be passed to NewKind in order to add extra deployments to setup the
// test scenario.
func AddDeployments(defs ...Deployment) Option {
	return func(k *Kind) {
		k.deployManifests = append(k.deployManifests, defs...)
	}
}

// NewKind creates a kind cluster given a name and set of Option instances. The base dir
// must point to the folder where the logs are going to be stored and, in case your docker
// backend doesn't provide access to the local images, where the ebpf-agent.tar container image
// is located. Usually it will be the project root.
func NewKind(kindClusterName, baseDir string, options ...Option) *Kind {
	k := &Kind{
		testEnv:         env.New(),
		baseDir:         baseDir,
		clusterName:     kindClusterName,
		deployManifests: defaultBaseDeployments,
	}
	for _, option := range options {
		option(k)
	}
	return k
}

// Run the Kind cluster for the later execution of tests.
func (k *Kind) Run(m *testing.M) {
	envFuncs := []env.Func{
		envfuncs.CreateKindClusterWithConfig(k.clusterName,
			kindImage,
			path.Join(packageDir(), "base", "00-kind.yml")),
		k.loadLocalImage(),
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
			k.exportLogs(),
			envfuncs.DestroyKindCluster(k.clusterName),
		).Run(m)
	log.WithField("returnCode", code).Info("tests finished run")
}

// export logs into the e2e-logs folder of the base directory.
func (k *Kind) exportLogs() env.Func {
	return func(ctx context.Context, config *envconf.Config) (context.Context, error) {
		logsDir := path.Join(k.baseDir, logsSubDir)
		log.WithField("directory", logsDir).Info("exporting cluster logs")
		exe := gexe.New()
		out := exe.Run("kind export logs " + logsDir + " --name " + k.clusterName)
		log.WithField("out", out).Debug("exported cluster logs")
		return ctx, nil
	}
}

func (k *Kind) TestEnv() env.Environment {
	return k.testEnv
}

// Loki client pointing to the Loki instance inside the test cluster
func (k *Kind) Loki() *tester.Loki {
	return &tester.Loki{BaseURL: "http://127.0.0.1:30100"}
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

// deploys a yaml manifest file
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
			if !errors.Is(err, io.EOF) {
				return fmt.Errorf("decoding manifest raw object: %w", err)
			}
			return nil
		}

		obj, gvk, err := yaml.NewDecodingSerializer(unstructured.UnstructuredJSONScheme).Decode(rawObj.Raw, nil, nil)
		if err != nil {
			return fmt.Errorf("creating yaml decoding serializer: %w", err)
		}
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

// loadLocalImage loads the agent docker image into the test cluster. It tries both available
// methods, which will selectively work depending on the container backend type
func (k *Kind) loadLocalImage() env.Func {
	return func(ctx context.Context, config *envconf.Config) (context.Context, error) {
		log.Debug("trying to load docker image from local registry")
		ctx, err := envfuncs.LoadDockerImageToCluster(
			k.clusterName, agentContainerName)(ctx, config)
		if err == nil {
			return ctx, nil
		}
		log.WithError(err).WithField("archive", localArchiveName).
			Debug("couldn't load image from local registry. Trying from local archive")
		return envfuncs.LoadImageArchiveToCluster(
			k.clusterName, path.Join(k.baseDir, localArchiveName))(ctx, config)
	}
}

// withTimeout retries the execution of an env.Func until it succeeds or a timeout is reached
func withTimeout(f env.Func) env.Func {
	tlog := log.WithField("function", "withTimeout")
	return func(ctx context.Context, config *envconf.Config) (context.Context, error) {
		start := time.Now()
		for {
			ctx, err := f(ctx, config)
			if err == nil {
				return ctx, nil
			}
			if time.Since(start) > timeout {
				return ctx, fmt.Errorf("timeout (%s) trying to execute function: %w", timeout, err)
			}
			tlog.WithError(err).Debug("function did not succeed. Retrying after 1s")
			time.Sleep(time.Second)
		}
	}
}

// isReady succeeds if the passed deployment does not have ReadyFunction, or it succeeds
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
