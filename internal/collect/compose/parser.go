package compose

import (
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// File represents parsed compose with line info.
type File struct {
	Path     string
	Content  string
	Services []Service
	Networks map[string]Network
	// Raw node kept for advanced line queries if needed
	root *yaml.Node
}

// Service holds name + relevant fields with lines where possible.
type Service struct {
	Name        string
	Image       string
	ImageLine   int
	Ports       []PortMapping
	PortsLine   int // line of the 'ports:' key if present
	Volumes     []string
	VolumesLine int // line of the 'volumes:' key if present
	Privileged  bool
	PrivLine    int
	Environment []string // "KEY=val" entries (from map or list form)
	EnvLine     int      // line of the 'environment:' key if present
	// Raw for future
}

type PortMapping struct {
	HostPort   int
	TargetPort int
	Raw        string // original "11434:11434" or "127.0.0.1:..."
	Line       int
}

type Network struct {
	Internal bool
	Line     int
}

// Parse reads compose and extracts using yaml nodes to preserve line numbers.
func Parse(path string) (*File, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	content := string(b)

	var root yaml.Node
	if err := yaml.Unmarshal(b, &root); err != nil {
		return nil, err
	}

	f := &File{
		Path:    path,
		Content: content,
		root:    &root,
	}

	// Find the document node
	doc := &root
	if len(root.Content) > 0 {
		doc = root.Content[0]
	}

	// services map is under key "services"
	servicesNode := getMapValue(doc, "services")
	if servicesNode != nil && servicesNode.Kind == yaml.MappingNode {
		for i := 0; i < len(servicesNode.Content); i += 2 {
			nameNode := servicesNode.Content[i]
			svcNode := servicesNode.Content[i+1]
			svc := Service{Name: nameNode.Value}
			// image
			imgNode := getMapValue(svcNode, "image")
			if imgNode != nil {
				svc.Image = imgNode.Value
				svc.ImageLine = imgNode.Line
			}
			// ports
			portsNode := getMapValue(svcNode, "ports")
			if portsNode != nil {
				svc.PortsLine = portsNode.Line
				for _, pnode := range portsNode.Content {
					pm := parsePort(pnode)
					if pm != nil {
						svc.Ports = append(svc.Ports, *pm)
					}
				}
			}
			// privileged
			privNode := getMapValue(svcNode, "privileged")
			if privNode != nil && (privNode.Value == "true" || privNode.Value == "yes") {
				svc.Privileged = true
				svc.PrivLine = privNode.Line
			}
			// volumes for broad mounts later
			volsNode := getMapValue(svcNode, "volumes")
			if volsNode != nil {
				svc.VolumesLine = volsNode.Line
				for _, v := range volsNode.Content {
					svc.Volumes = append(svc.Volumes, v.Value)
				}
			}
			// environment: for CORS checks + secret key names (values not retained long-term)
			envNode := getMapValue(svcNode, "environment")
			if envNode != nil {
				svc.EnvLine = envNode.Line
				if envNode.Kind == yaml.MappingNode {
					for i := 0; i < len(envNode.Content); i += 2 {
						k := envNode.Content[i].Value
						v := envNode.Content[i+1].Value
						svc.Environment = append(svc.Environment, k+"="+v)
					}
				} else if envNode.Kind == yaml.SequenceNode {
					for _, e := range envNode.Content {
						svc.Environment = append(svc.Environment, e.Value)
					}
				}
			}
			f.Services = append(f.Services, svc)
		}
	}

	// networks
	netsNode := getMapValue(doc, "networks")
	if netsNode != nil {
		f.Networks = map[string]Network{}
		for i := 0; i < len(netsNode.Content); i += 2 {
			netName := netsNode.Content[i].Value
			netNode := netsNode.Content[i+1]
			n := Network{}
			intNode := getMapValue(netNode, "internal")
			if intNode != nil && (intNode.Value == "true" || intNode.Value == "yes") {
				n.Internal = true
			}
			n.Line = netsNode.Content[i].Line
			f.Networks[netName] = n
		}
	}

	return f, nil
}

func getMapValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(node.Content); i += 2 {
		k := node.Content[i]
		if k.Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func parsePort(node *yaml.Node) *PortMapping {
	if node == nil {
		return nil
	}
	line := node.Line
	clean := func(s string) string { return strings.Trim(s, `"' `) }

	// Handle long-form map ports:
	// - target: 8080
	//   published: "127.0.0.1:3000"
	// or
	// - published: 3000
	//   target: 8080
	if node.Kind == yaml.MappingNode {
		pubNode := getMapValue(node, "published")
		tgtNode := getMapValue(node, "target")
		var raw string
		var hp, tp int
		if pubNode != nil {
			raw = pubNode.Value
			pv := clean(pubNode.Value)
			pparts := splitPortRaw(pv)
			if len(pparts) == 1 {
				if n, ok := atoiSafe(pparts[0]); ok {
					hp = n
				}
			} else if len(pparts) >= 2 {
				// ip:port or port:something
				last := clean(pparts[len(pparts)-1])
				if n, ok := atoiSafe(last); ok {
					hp = n
				}
			}
		}
		if tgtNode != nil {
			if n, ok := atoiSafe(clean(tgtNode.Value)); ok {
				tp = n
			}
		}
		return &PortMapping{Raw: raw, Line: line, HostPort: hp, TargetPort: tp}
	}

	// scalar / short form
	raw := node.Value
	if raw == "" && len(node.Content) > 0 {
		raw = node.Value
	}
	if raw == "" {
		return nil
	}
	pm := &PortMapping{Raw: raw, Line: line}
	parts := splitPortRaw(raw)
	if len(parts) == 1 {
		p := clean(parts[0])
		if n, ok := atoiSafe(p); ok {
			pm.HostPort = n
			pm.TargetPort = n
		}
	} else if len(parts) >= 2 {
		first := clean(parts[0])
		second := clean(parts[1])
		last := clean(parts[len(parts)-1])
		if strings.Contains(first, ".") || strings.Contains(first, ":") {
			if n, ok := atoiSafe(second); ok {
				pm.HostPort = n
			}
			if n, ok := atoiSafe(last); ok {
				pm.TargetPort = n
			}
		} else {
			if n, ok := atoiSafe(first); ok {
				pm.HostPort = n
			}
			if n, ok := atoiSafe(last); ok {
				pm.TargetPort = n
			}
		}
	}
	return pm
}

func splitPortRaw(s string) []string {
	// handle ip:port:port or port:port
	s = strings.Trim(s, " \t")
	if idx := strings.IndexAny(s, " "); idx >= 0 {
		s = s[:idx]
	}
	// remove protocol suffix
	if i := strings.LastIndex(s, "/"); i > 0 {
		s = s[:i]
	}
	return strings.Split(s, ":")
}

func atoiSafe(s string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	return n, err == nil
}
