package kubernetes

import (
	"github.com/stretchr/testify/mock"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

type KubeDataMock struct {
	mock.Mock
	kubeDataInterface
}

func (o *KubeDataMock) InitFromConfig(kubeConfigPath string) error {
	args := o.Called(kubeConfigPath)
	return args.Error(0)
}

type IndexerMock struct {
	mock.Mock
	cache.Indexer
}

type InformerMock struct {
	mock.Mock
	InformerInterface
}

type InformerInterface interface {
	cache.SharedInformer
	AddIndexers(indexers cache.Indexers) error
	GetIndexer() cache.Indexer
}

func (m *IndexerMock) ByIndex(indexName, indexedValue string) ([]interface{}, error) {
	args := m.Called(indexName, indexedValue)
	return args.Get(0).([]interface{}), args.Error(1)
}

func (m *IndexerMock) GetByKey(key string) (interface{}, bool, error) {
	args := m.Called(key)
	return args.Get(0), args.Bool(1), args.Error(2)
}

func (m *InformerMock) GetIndexer() cache.Indexer {
	args := m.Called()
	return args.Get(0).(cache.Indexer)
}

func (m *IndexerMock) MockPod(ip, name, namespace, nodeIP string, owner *Owner) {
	var ownerRef []metav1.OwnerReference
	if owner != nil {
		ownerRef = []metav1.OwnerReference{{
			Kind: owner.Type,
			Name: owner.Name,
		}}
	}
	m.On("ByIndex", IndexIP, ip).Return([]interface{}{&Info{
		Type: "Pod",
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       namespace,
			OwnerReferences: ownerRef,
		},
		HostIP: nodeIP,
	}}, nil)
}

func (m *IndexerMock) MockNode(ip, name string) {
	m.On("ByIndex", IndexIP, ip).Return([]interface{}{&Info{
		Type:       "Node",
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}}, nil)
}

func (m *IndexerMock) MockService(ip, name, namespace string) {
	m.On("ByIndex", IndexIP, ip).Return([]interface{}{&Info{
		Type:       "Service",
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
	}}, nil)
}

func (m *IndexerMock) MockReplicaSet(name, namespace string, owner Owner) {
	m.On("GetByKey", namespace+"/"+name).Return(&metav1.ObjectMeta{
		Name: name,
		OwnerReferences: []metav1.OwnerReference{{
			Kind: owner.Type,
			Name: owner.Name,
		}},
	}, true, nil)
}

func (m *IndexerMock) FallbackNotFound() {
	m.On("ByIndex", IndexIP, mock.Anything).Return([]interface{}{}, nil)
}

func SetupIndexerMocks(kd *KubeData) (pods, nodes, svc, rs *IndexerMock) {
	// pods informer
	pods = &IndexerMock{}
	pim := InformerMock{}
	pim.On("GetIndexer").Return(pods)
	kd.pods = &pim
	// nodes informer
	nodes = &IndexerMock{}
	him := InformerMock{}
	him.On("GetIndexer").Return(nodes)
	kd.nodes = &him
	// svc informer
	svc = &IndexerMock{}
	sim := InformerMock{}
	sim.On("GetIndexer").Return(svc)
	kd.services = &sim
	// rs informer
	rs = &IndexerMock{}
	rim := InformerMock{}
	rim.On("GetIndexer").Return(rs)
	kd.replicaSets = &rim
	return
}
