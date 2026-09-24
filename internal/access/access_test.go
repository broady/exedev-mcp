package access

import (
	"reflect"
	"testing"
)

func TestPolicy(t *testing.T) {
	web := VM{Name: "web", Tags: []string{"prod"}}
	dev := VM{Name: "dev"}
	for _, tc := range []struct {
		name       string
		p          Policy
		valid      bool
		web, dev   bool
		str        string
		tagsForDev bool
	}{
		{"zero", Policy{}, false, false, false, "no VMs: list only", false},
		{"full", Full(), true, true, true, "all VMs: read, write, run, restart, manage", false},
		{"all VMs with extras", Policy{AllVMs: true, VMs: []string{"web"}}, false, true, true, "all VMs: list only", false},
		{"by name", Policy{VMs: []string{"dev"}, Ops: []Op{OpRead}}, true, false, true, "dev: read", false},
		{"by tag", Policy{Tags: []string{"prod"}}, true, true, false, "tag:prod: list only", true},
		{"both", Policy{VMs: []string{"dev"}, Tags: []string{"prod"}}, true, true, true, "dev, tag:prod: list only", false},
		{"bad name", Policy{VMs: []string{"Web!"}}, false, false, false, "Web!: list only", false},
		{"bad tag", Policy{Tags: []string{"a b"}}, false, false, false, "tag:a b: list only", true},
		{"unknown op", Policy{AllVMs: true, Ops: []Op{"sudo"}}, false, true, true, "all VMs: sudo", false},
		{"manage without all VMs", Policy{VMs: []string{"dev"}, Ops: []Op{OpManage}}, false, false, true, "dev: manage", false},
	} {
		if err := tc.p.Validate(); (err == nil) != tc.valid {
			t.Errorf("%s: Validate() = %v, want valid=%v", tc.name, err, tc.valid)
		}
		if got := tc.p.Allows(web); got != tc.web {
			t.Errorf("%s: Allows(web) = %v", tc.name, got)
		}
		if got := tc.p.Allows(dev); got != tc.dev {
			t.Errorf("%s: Allows(dev) = %v", tc.name, got)
		}
		if got := tc.p.String(); got != tc.str {
			t.Errorf("%s: String() = %q, want %q", tc.name, got, tc.str)
		}
		if got := tc.p.NeedsTags("dev"); got != tc.tagsForDev {
			t.Errorf("%s: NeedsTags(dev) = %v", tc.name, got)
		}
	}
}

func TestNormalizeOps(t *testing.T) {
	got := NormalizeOps([]Op{OpRun, "bogus", OpRead, OpRun})
	if want := []Op{OpRead, OpRun}; !reflect.DeepEqual(got, want) {
		t.Errorf("NormalizeOps = %v, want %v", got, want)
	}
}

func TestCloneIsDeep(t *testing.T) {
	p := Policy{VMs: []string{"a"}, Tags: []string{"t"}, Ops: []Op{OpRead}}
	c := p.Clone()
	c.VMs[0], c.Tags[0], c.Ops[0] = "b", "u", OpRun
	if p.VMs[0] != "a" || p.Tags[0] != "t" || p.Ops[0] != OpRead {
		t.Error("Clone shares backing arrays")
	}
}
