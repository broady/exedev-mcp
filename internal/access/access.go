// Package access defines what a connection may do: which VMs, and which
// operations on them.
package access

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Op is a group of tools a connection may use. list_vms is always
// available.
type Op string

const (
	OpRead    Op = "read"    // read_file
	OpWrite   Op = "write"   // write_file, edit_file
	OpRun     Op = "run"     // run_command
	OpRestart Op = "restart" // restart_vm
	// OpManage acts on the account rather than one VM: create_vm,
	// delete_vm, exe_command. It requires AllVMs.
	OpManage Op = "manage"
)

// Ops lists every operation in display order.
func Ops() []Op { return []Op{OpRead, OpWrite, OpRun, OpRestart, OpManage} }

// Policy limits a connection. The zero value allows nothing but listing.
type Policy struct {
	// AllVMs allows every VM. Otherwise VMs and Tags select them.
	AllVMs bool `json:"all_vms,omitempty"`
	// VMs are allowed by name.
	VMs []string `json:"vms,omitempty"`
	// Tags allow any VM carrying one of them, including VMs tagged later.
	Tags []string `json:"tags,omitempty"`
	// Ops are the allowed operations, in Ops() order.
	Ops []Op `json:"ops,omitempty"`
}

// Full allows everything.
func Full() Policy { return Policy{AllVMs: true, Ops: Ops()} }

// VM is what the policy needs to know about a VM.
type VM struct {
	Name string
	Tags []string
}

var (
	vmNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	// exe.dev does not document tag syntax; tags are picked from what `ls`
	// reports, so only reject what could never be a tag.
	tagRE = regexp.MustCompile(`^[^\s\x00-\x1f\x7f]{1,64}$`)
)

// Validate reports whether p is well formed.
func (p Policy) Validate() error {
	if p.AllVMs && (len(p.VMs) > 0 || len(p.Tags) > 0) {
		return errors.New("access: an all-VMs policy lists no VMs or tags")
	}
	if !p.AllVMs && len(p.VMs) == 0 && len(p.Tags) == 0 {
		return errors.New("pick at least one VM or tag")
	}
	for _, v := range p.VMs {
		if !vmNameRE.MatchString(v) {
			return fmt.Errorf("invalid VM name %q", v)
		}
	}
	for _, t := range p.Tags {
		if !tagRE.MatchString(t) {
			return fmt.Errorf("invalid tag %q", t)
		}
	}
	for _, op := range p.Ops {
		if !slices.Contains(Ops(), op) {
			return fmt.Errorf("unknown operation %q", op)
		}
	}
	if p.Can(OpManage) && !p.AllVMs {
		return errors.New("manage needs access to all VMs")
	}
	return nil
}

// NormalizeOps returns ops deduplicated in Ops() order, dropping unknown
// values.
func NormalizeOps(ops []Op) []Op {
	return slices.DeleteFunc(Ops(), func(op Op) bool { return !slices.Contains(ops, op) })
}

// Can reports whether p allows op.
func (p Policy) Can(op Op) bool { return slices.Contains(p.Ops, op) }

// Allows reports whether p covers vm.
func (p Policy) Allows(vm VM) bool {
	if p.AllVMs || slices.Contains(p.VMs, vm.Name) {
		return true
	}
	return slices.ContainsFunc(vm.Tags, func(t string) bool { return slices.Contains(p.Tags, t) })
}

// NeedsTags reports whether deciding on name requires looking up the VM's
// tags, which costs an API call.
func (p Policy) NeedsTags(name string) bool {
	return !p.AllVMs && !slices.Contains(p.VMs, name) && len(p.Tags) > 0
}

// Clone returns a deep copy.
func (p Policy) Clone() Policy {
	return Policy{AllVMs: p.AllVMs, VMs: slices.Clone(p.VMs), Tags: slices.Clone(p.Tags), Ops: slices.Clone(p.Ops)}
}

// Scope describes the VMs, e.g. "all VMs" or "web, tag:prod".
func (p Policy) Scope() string {
	if p.AllVMs {
		return "all VMs"
	}
	parts := slices.Clone(p.VMs)
	for _, t := range p.Tags {
		parts = append(parts, "tag:"+t)
	}
	if len(parts) == 0 {
		return "no VMs"
	}
	return strings.Join(parts, ", ")
}

// String describes p, e.g. "all VMs: read, run".
func (p Policy) String() string {
	ops := "list only"
	if len(p.Ops) > 0 {
		s := make([]string, len(p.Ops))
		for i, op := range p.Ops {
			s[i] = string(op)
		}
		ops = strings.Join(s, ", ")
	}
	return p.Scope() + ": " + ops
}
