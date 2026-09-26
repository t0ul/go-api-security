package deps

import (
	"runtime/debug"
	"sort"
)

type Finding struct {
	Path     string `json:"path"`
	Version  string `json:"version"`
	Min      string `json:"min,omitempty"`
	OK       bool   `json:"ok"`
	Replaced bool   `json:"replaced"`
}

// EvaluateBuild returns current module versions with policy compliance.
func EvaluateBuild() ([]Finding, error) {
	bi, ok := debug.ReadBuildInfo()
	if !ok { // not built with module info
		return nil, nil
	}
	var out []Finding
	seen := map[string]bool{}

	add := func(path, version string, replaced bool) {
		min := MinPolicy[path]
		ok := true
		if min != "" && version != "" {
			ok = Compare(version, min) >= 0
		}
		out = append(out, Finding{Path: path, Version: version, Min: min, OK: ok, Replaced: replaced})
		seen[path] = true
	}

	// Main module appears in bi.Main
	if bi.Main.Path != "" {
		v := bi.Main.Version
		if v == "" {
			v = "(devel)"
		}
		add(bi.Main.Path, v, bi.Main.Replace != nil)
	}
	for _, m := range bi.Deps {
		v := ""
		if m.Version != "" {
			v = m.Version
		}
		repl := false
		if m.Replace != nil {
			repl = true
			if m.Replace.Version != "" {
				v = m.Replace.Version
			} else if m.Replace.Path != "" {
				v = "(replace " + m.Replace.Path + ")"
			}
		}
		add(m.Path, v, repl)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}
