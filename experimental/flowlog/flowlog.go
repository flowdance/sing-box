package flowlog

import (
	"context"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/trafficcontrol"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/observable"
	"github.com/sagernet/sing/service"
)

const (
	batchSize         = 512
	flushInterval     = 500 * time.Millisecond
	retentionInterval = 6 * time.Hour
	defaultRetention  = 30
)

// Service is a lifecycle service that subscribes to the trafficcontrol
// Manager's connection-closed events and persists each as a SQLite row.
type Service struct {
	ctx       context.Context
	cancel    context.CancelFunc
	manager   *trafficcontrol.Manager
	opts      option.FlowLogOptions
	retention int
	logger    log.ContextLogger
	store     *store
	sub       observable.Subscription[trafficcontrol.ConnectionEvent]
	done      chan struct{}
}

func New(ctx context.Context, opts option.FlowLogOptions, logger log.ContextLogger) (*Service, error) {
	manager := service.PtrFromContext[trafficcontrol.Manager](ctx)
	if manager == nil {
		return nil, E.New("missing traffic manager")
	}
	return &Service{
		ctx:     ctx,
		manager: manager,
		opts:    opts,
		logger:  logger,
	}, nil
}

func (s *Service) Name() string {
	return "flowlog"
}

func (s *Service) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	path := s.opts.Path
	if path == "" {
		path = "flowlog.db"
	}
	st, err := openStore(path)
	if err != nil {
		return E.Cause(err, "open flowlog db")
	}
	s.store = st
	s.retention = s.opts.RetentionDays
	if s.retention <= 0 {
		s.retention = defaultRetention
	}
	s.ctx, s.cancel = context.WithCancel(s.ctx)
	s.done = make(chan struct{})
	sub, subDone, err := s.manager.SubscribeEvents()
	if err != nil {
		s.cancel()
		s.cancel = nil
		s.done = nil
		s.store = nil
		_ = st.close()
		return E.Cause(err, "subscribe traffic events")
	}
	s.sub = sub
	go s.consume(sub, subDone)
	go s.retentionLoop()
	return nil
}

func (s *Service) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	if s.done != nil {
		<-s.done // wait for the consumer to drain and flush
	}
	if s.sub != nil {
		s.manager.UnSubscribeEvents(s.sub)
		s.sub = nil
	}
	if s.store != nil {
		return s.store.close()
	}
	return nil
}

func (s *Service) consume(ch <-chan trafficcontrol.ConnectionEvent, subDone <-chan struct{}) {
	defer close(s.done)
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()
	var batch []record
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := s.store.insertBatch(batch); err != nil {
			s.logger.Error("flowlog insert: ", err)
		}
		batch = batch[:0]
	}
	for {
		select {
		case ev := <-ch:
			if ev.Type == trafficcontrol.ConnectionEventClosed && ev.Metadata != nil {
				batch = append(batch, metadataToRecord(ev.Metadata))
				if len(batch) >= batchSize {
					flush()
				}
			}
		case <-ticker.C:
			flush()
		case <-s.ctx.Done():
			// Shutdown: inbounds close before this service, so a burst of closed
			// events may still arrive. Drain whatever is buffered, then flush.
			draining := true
			for draining {
				select {
				case ev := <-ch:
					if ev.Type == trafficcontrol.ConnectionEventClosed && ev.Metadata != nil {
						batch = append(batch, metadataToRecord(ev.Metadata))
					}
				default:
					draining = false
				}
			}
			flush()
			return
		case <-subDone:
			flush()
			return
		}
	}
}

func (s *Service) retentionLoop() {
	s.runRetention()
	ticker := time.NewTicker(retentionInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.runRetention()
		}
	}
}

func (s *Service) runRetention() {
	if err := s.store.deleteOld(s.retention); err != nil {
		s.logger.Error("flowlog retention: ", err)
	}
}
