package samples // import "go.opentelemetry.io/ebpf-profiler/reporter/samples"

import (
	"bytes"
	"fmt"
	"os"
	"time"

	lru "github.com/elastic/go-freelru"
	log "github.com/sirupsen/logrus"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

const (
	PodEnvCacheElements = 2048
	PodEnvCacheLifeTime = 90 * time.Second
)

type podEnv struct {
	podName string
	appCode string
	deployTag     string
}

type QunarSampleAttrProducer struct {
	// podEnvID caches PID to pod env for containers.
	podEnvID *lru.SyncedLRU[libpf.PID, *podEnv]
}

func NewQunarSampleAttrProducer() (*QunarSampleAttrProducer, error) {
	podEnvID, err := lru.NewSynced[libpf.PID, *podEnv](PodEnvCacheElements,
		func(pid libpf.PID) uint32 { return uint32(pid) })
	if err != nil {
		return nil, err
	}
	// Set a lifetime to reduce risk of invalid data in case of PID reuse.
	podEnvID.SetLifetime(PodEnvCacheLifeTime)

	// TODO need purge qunarAttrID in seperate goroutine

	return &QunarSampleAttrProducer{ podEnvID: podEnvID, }, nil
}

func (p *QunarSampleAttrProducer) lookupPodEnv(pid libpf.PID) (*podEnv, error) {
	env, ok := p.podEnvID.Get(pid)
	if ok {
		return env, nil
	}

	// Slow path
	env = readPodEnv(pid)

	// Cache the pod env information
	p.podEnvID.Add(pid, env)

	return env, nil
}

func readPodEnv(pid libpf.PID) *podEnv {
    content, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
    if err != nil {
		log.Debugf("read pid env failed, will ignore. err: %v", err)
        return &podEnv{
			podName: "",
			appCode: "",
			deployTag: "",
		}
    }

    envVars := bytes.Split(content, []byte{0})
    kvs := make(map[string]string)

    for _, envVar := range envVars {
        if len(envVar) == 0 {
            continue
        }

        parts := bytes.SplitN(envVar, []byte{'='}, 2)
        if len(parts) != 2 {
            continue
        }

        key := string(parts[0])
        value := string(parts[1])
        kvs[key] = value
    }

    return &podEnv{
        podName: kvs["POD_NAME"],
    	appCode: kvs["app_code"],
        deployTag: kvs["output_tag"],
    }
}

func (p *QunarSampleAttrProducer) CollectExtraSampleMeta(trace *libpf.Trace, meta *TraceEventMeta) any {
	podEnv, err := p.lookupPodEnv(meta.PID)
	if err != nil {
		log.Errorf("failed to lookup qunar attr: %v", err)
		return nil
	}
	return podEnv
}

func (p *QunarSampleAttrProducer) ExtraSampleAttrs(attrMgr *AttrTableManager, meta any) []int32 {
	attrIndices := pcommon.NewInt32Slice()
	if env, ok := meta.(*podEnv); ok {
		attrMgr.AppendOptionalString(attrIndices, semconv.K8SPodNameKey, env.podName)
		attrMgr.AppendOptionalString(attrIndices, attribute.Key("qunar.app.code"), env.appCode)
		attrMgr.AppendOptionalString(attrIndices, attribute.Key("qunar.deploy.tag"), env.deployTag)
	}
	return attrIndices.AsRaw()
}
