package scanner

import (
	"sync"

	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

type Pool struct {
	size         int
	modules      block.Modules
	state        *state.State
	rules        []rule.Rule
	ignoreErrors bool
}

func NewPool(size int, rules []rule.Rule, modules []block.Module, state *state.State, ignoreErrors bool) *Pool {
	return &Pool{
		size:         size,
		rules:        rules,
		state:        state,
		modules:      modules,
		ignoreErrors: ignoreErrors,
	}
}

func (p *Pool) Run() rules.Results {

	outgoing := make(chan Job, p.size*2)

	var workers []*Worker
	for i := 0; i < p.size; i++ {
		worker := NewWorker(outgoing)
		go worker.Start()
		workers = append(workers, worker)
	}

	// run defsec checks
	for _, r := range GetRegisteredRules() {
		outgoing <- &infraRuleJob{
			state:        p.state,
			rule:         r,
			ignoreErrors: p.ignoreErrors,
		}
	}

	// run internal checks
	for _, module := range p.modules {
		for _, r := range GetRegisteredRules() {
			if r.CheckTerraform != nil {
				outgoing <- &hclModuleRuleJob{
					module:       module,
					rule:         r,
					ignoreErrors: p.ignoreErrors,
				}
			}
		}
	}

	close(outgoing)

	var results rules.Results
	for _, worker := range workers {
		results = append(results, worker.Wait()...)
	}

	return results
}

type Job interface {
	Run() rules.Results
}

type infraRuleJob struct {
	state *state.State
	rule  rule.Rule

	ignoreErrors bool
}

type hclModuleRuleJob struct {
	module       block.Module
	rule         rule.Rule
	ignoreErrors bool
}

func (h *infraRuleJob) Run() rules.Results {
	if h.ignoreErrors {
		defer h.rule.RecoverFromCheckPanic()
	}
	return h.rule.CheckAgainstState(h.state)
}

func (h *hclModuleRuleJob) Run() rules.Results {
	if h.ignoreErrors {
		defer h.rule.RecoverFromCheckPanic()
	}
	var results rules.Results
	for _, block := range h.module.GetBlocks() {
		results = append(results, h.rule.CheckAgainstBlock(block, h.module)...)
	}
	return results
}

type Worker struct {
	incoming <-chan Job
	mu       sync.Mutex
	results  rules.Results
}

func NewWorker(incoming <-chan Job) *Worker {
	return &Worker{
		incoming: incoming,
	}
}

func (w *Worker) Start() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.results = nil
	for job := range w.incoming {
		w.results = append(w.results, job.Run()...)
	}
}

func (w *Worker) Wait() rules.Results {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.results
}
