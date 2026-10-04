//go:build dae_stub_ebpf

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

// zz_parity_dump_test.go is the dae side of sodama's rule-compiler parity
// harness. It is NOT part of upstream dae: lab/parity/run.sh copies this file
// into a dae source checkout (lab/parity/dae-work) and drives it with
// `go test -tags dae_stub_ebpf ./control -run TestParityDump`.
//
// It compiles a sodama rules file (a `.dae` routing subset) through the same
// lowering path the daemon uses in NewControlPlaneWithContextOptions
// (control/control_plane.go): config_parser.Parse -> config.New ->
// routing.NewNormalizedProgram (production optimizer chain) ->
// NewRoutingMatcherBuilderFromProgram -> KernspaceSnapshot + BuildUserspace.
// The snapshot is the exact []bpfMatchSet + [][]netip.Prefix array that
// buildRoutingKernspaceForSlot would write into the BPF LPM maps.
//
// Output format (one line per match set, byte-for-byte what sodama's
// CompiledRules::dump contract expects):
//
//	slot <i> type=<Type> not=<0|1> outbound=0x<hex> mark=0x<hex> must=<0|1><payload>
//
// Environment:
//
//	PARITY_RULES  path of the rules file to compile (required)
//	PARITY_OUT    if set, the dump is also written verbatim to this file
package control

import (
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

// parityFallbackLine matches sodama's `fallback -> <outbound>` spelling
// (dae itself spells this as a `fallback: <outbound>` param inside the routing
// section, which is what the rewrite below feeds to the real config parser).
var parityFallbackLine = regexp.MustCompile(`^fallback\s*->\s*(.+?)\s*(?:#.*)?$`)

func TestParityDump(t *testing.T) {
	rulesPath := os.Getenv("PARITY_RULES")
	if rulesPath == "" {
		t.Fatal("PARITY_RULES is not set")
	}
	raw, err := os.ReadFile(rulesPath)
	if err != nil {
		t.Fatalf("read rules file: %v", err)
	}

	fallback := "direct"
	var ruleLines []string
	for _, line := range strings.Split(string(raw), "\n") {
		if m := parityFallbackLine.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			fallback = m[1]
			continue
		}
		ruleLines = append(ruleLines, line)
	}

	var cfgText strings.Builder
	cfgText.WriteString("global {\n}\nrouting {\n")
	for _, line := range ruleLines {
		cfgText.WriteString(line)
		cfgText.WriteString("\n")
	}
	fmt.Fprintf(&cfgText, "fallback: %s\n}\n", fallback)

	sections, err := config_parser.Parse(cfgText.String())
	if err != nil {
		t.Fatalf("config_parser.Parse: %v", err)
	}
	conf, err := config.New(sections)
	if err != nil {
		t.Fatalf("config.New: %v", err)
	}

	log := logrus.New()
	log.SetOutput(io.Discard)

	// Production optimizer chain, exactly as in
	// control/control_plane.go NewControlPlaneWithContextOptions.
	// AliasOptimizer is what makes dae accept the `dip`/`dport` aliases; the
	// others are part of the run path and change rule/param ordering for some
	// inputs, so skipping them would not be parity with what reaches the BPF
	// maps. P17a: DatReaderOptimizer now resolves `geoip:`/`geosite:` params
	// via assets.LocationFinder (search dirs = DAE_LOCATION_ASSET etc.).
	program, err := routing.NewNormalizedProgram(conf.Routing.Rules, conf.Routing.Fallback,
		&routing.AliasOptimizer{},
		&routing.DatReaderOptimizer{Logger: log, LocationFinder: assets.NewLocationFinder(nil)},
		&routing.MergeAndSortRulesOptimizer{},
		&routing.DeduplicateParamsOptimizer{},
	)
	if err != nil {
		t.Fatalf("routing.NewNormalizedProgram: %v", err)
	}

	builder, err := NewRoutingMatcherBuilderFromProgram(log, program, map[string]uint8{
		"direct": uint8(consts.OutboundDirect),
		"block":  uint8(consts.OutboundBlock),
		"proxy":  uint8(consts.OutboundUserDefinedMin),
	}, nil)
	if err != nil {
		t.Fatalf("NewRoutingMatcherBuilderFromProgram: %v", err)
	}

	// KernspaceSnapshot is taken exactly where the daemon takes it and holds
	// the arrays the kernel-space writer consumes. BuildUserspace afterwards
	// runs the production validation (fallback last, tries buildable) without
	// touching bpf objects.
	snapshot := builder.KernspaceSnapshot()
	if snapshot == nil {
		t.Fatal("nil kernspace snapshot")
	}
	if _, err := builder.BuildUserspace(); err != nil {
		t.Fatalf("BuildUserspace: %v", err)
	}

	dump := parityFormatDump(t, snapshot.rules, snapshot.simulatedLpmTries)
	if outPath := os.Getenv("PARITY_OUT"); outPath != "" {
		if err := os.WriteFile(outPath, []byte(dump), 0o644); err != nil {
			t.Fatalf("write PARITY_OUT: %v", err)
		}
	}
	fmt.Fprint(os.Stdout, dump)
}

// parityLpmKey mirrors the _bpfLpmKey a prefix lowers to in control/bpf_utils.go
// cidrToBpfLpmKey (that file is excluded under the dae_stub_ebpf tag, so the
// conversion is replicated here; keep it identical).
type parityLpmKey struct {
	plen uint32
	data [16]byte
}

func parityBpfKey(p netip.Prefix) parityLpmKey {
	bits := p.Bits()
	addr := p.Addr()
	if addr.Is4In6() && bits <= 32 {
		// IPv4-mapped prefix written with an IPv4 bit count: unmap first and
		// re-add the 96-bit mapping offset below, exactly as cidrToBpfLpmKey.
		addr = addr.Unmap()
	}
	if addr.Is4() {
		bits += 96
	}
	return parityLpmKey{plen: uint32(bits), data: addr.As16()}
}

func parityRenderKey(k parityLpmKey) string {
	if k.data[10] == 0xff && k.data[11] == 0xff {
		plen := uint32(0)
		if k.plen > 96 {
			plen = k.plen - 96
		}
		return fmt.Sprintf("%d.%d.%d.%d/%d", k.data[12], k.data[13], k.data[14], k.data[15], plen)
	}
	// P16: real IPv6 prefix (non-v4-mapped) — canonical RFC5952 text, same
	// rendering as the Rust dumper's Ipv6Addr Display.
	addr := netip.AddrFrom16(k.data)
	return fmt.Sprintf("%s/%d", addr.String(), k.plen)
}

func parityTypeName(t uint8) string {
	switch consts.MatchType(t) {
	case consts.MatchType_IpSet:
		return "IpSet"
	case consts.MatchType_SourceIpSet:
		return "SourceIpSet"
	case consts.MatchType_Port:
		return "Port"
	case consts.MatchType_SourcePort:
		return "SourcePort"
	case consts.MatchType_L4Proto:
		return "L4Proto"
	case consts.MatchType_IpVersion:
		return "IpVersion"
	case consts.MatchType_Mac:
		return "Mac"
	case consts.MatchType_ProcessName:
		return "Pname"
	case consts.MatchType_Dscp:
		return "Dscp"
	case consts.MatchType_Fallback:
		return "Fallback"
	default:
		return fmt.Sprintf("Unknown(%d)", t)
	}
}

func parityFormatDump(t *testing.T, rules []bpfMatchSet, lpmTries [][]netip.Prefix) string {
	t.Helper()
	var b strings.Builder
	for i, m := range rules {
		fmt.Fprintf(&b, "slot %d type=%s not=%d outbound=0x%02x mark=0x%x must=%d",
			i, parityTypeName(m.Type), m.Not, m.Outbound, m.Mark, m.Must)
		switch consts.MatchType(m.Type) {
		case consts.MatchType_IpSet, consts.MatchType_SourceIpSet, consts.MatchType_Mac:
			idx := nativeBpfABI.uint32(m.Value[:4])
			if int(idx) >= len(lpmTries) {
				t.Fatalf("slot %d: lpm index %d out of range (%d tries)", i, idx, len(lpmTries))
			}
			keys := make([]parityLpmKey, 0, len(lpmTries[idx]))
			for _, p := range lpmTries[idx] {
				keys = append(keys, parityBpfKey(p))
			}
			// Dump order contract: prefix length ascending, then address
			// bytes ascending.
			sort.Slice(keys, func(a, c int) bool {
				if keys[a].plen != keys[c].plen {
					return keys[a].plen < keys[c].plen
				}
				return bytes.Compare(keys[a].data[:], keys[c].data[:]) < 0
			})
			parts := make([]string, len(keys))
			for j, k := range keys {
				parts[j] = parityRenderKey(k)
			}
			fmt.Fprintf(&b, " prefixes=%s", strings.Join(parts, ","))
		case consts.MatchType_Port, consts.MatchType_SourcePort:
			start := nativeBpfABI.uint16(m.Value[:2])
			end := nativeBpfABI.uint16(m.Value[2:4])
			fmt.Fprintf(&b, " port=%d-%d", start, end)
		case consts.MatchType_L4Proto, consts.MatchType_IpVersion:
			fmt.Fprintf(&b, " mask=0x%x", nativeBpfABI.uint32(m.Value[:4]))
		case consts.MatchType_Dscp:
			fmt.Fprintf(&b, " dscp=%d", m.Value[0])
		case consts.MatchType_ProcessName:
			// P17b：pname 16B 定长（NUL 截断渲染），与 Rust fmt_pname 一致。
			v := m.Value[:]
			if i := bytes.IndexByte(v, 0); i >= 0 {
				v = v[:i]
			}
			fmt.Fprintf(&b, " pname=%s", string(v))
		case consts.MatchType_Fallback:
			// No payload.
		default:
			t.Fatalf("slot %d: unhandled match type %d", i, m.Type)
		}
		b.WriteString("\n")
	}
	return b.String()
}
