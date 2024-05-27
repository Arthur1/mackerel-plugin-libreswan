package main

import (
	"bytes"
	"flag"
	"fmt"
	"os/exec"
	"regexp"
	"slices"
	"strconv"

	mp "github.com/mackerelio/go-mackerel-plugin"
)

func main() {
	plugin := new(Plugin)

	dockerExec := flag.String("docker-exec", "", "docker container name which contains ipsec command")
	tempfile := flag.String("tempfile", "", "temp file name")
	flag.Parse()
	if *dockerExec == "" {
		plugin.Command = []string{"ipsec"}
	} else {
		plugin.Command = []string{"docker", "exec", *dockerExec, "ipsec"}
	}

	mackerelPlugin := mp.NewMackerelPlugin(plugin)
	mackerelPlugin.Tempfile = *tempfile

	mackerelPlugin.Run()
}

type Plugin struct {
	Command []string
}

var _ mp.PluginWithPrefix = new(Plugin)

func (p *Plugin) FetchMetrics() (map[string]float64, error) {
	statusOut, err := p.ExecIPsecStatus()
	if err != nil {
		return nil, err
	}
	totalConnections, err := getTotalConnectionsFromIPsecStatusOutput(statusOut)
	if err != nil {
		return nil, err
	}
	ikeSAs, err := getIKESAsFromIPsecStatusOutput(statusOut)
	if err != nil {
		return nil, err
	}
	ipsecSAs, err := getIPsecSAsFromIPsecStatusOutput(statusOut)
	if err != nil {
		return nil, err
	}

	// NOTE: https://github.com/mackerelio/go-mackerel-plugin library behaves strangely
	// for graph definitions that do not contain #.
	// Metric keys must be specified without including the prefix of graph definitions.
	// It means that metric names must be unique over all graph definitions.
	metrics := map[string]float64{
		"loaded":              float64(totalConnections.Loaded),
		"active":              float64(totalConnections.Active),
		"ike_total":           float64(ikeSAs.Total),
		"ike_half_open":       float64(ikeSAs.HalfOpen),
		"ike_open":            float64(ikeSAs.Open),
		"ike_authenticated":   float64(ikeSAs.Authenticated),
		"ike_anonymous":       float64(ikeSAs.Anonymous),
		"ipsec_total":         float64(ipsecSAs.Total),
		"ipsec_authenticated": float64(ipsecSAs.Authenticated),
		"ipsec_anonymous":     float64(ipsecSAs.Anonymous),
	}

	return metrics, nil
}

func (p *Plugin) GraphDefinition() map[string]mp.Graphs {
	return map[string]mp.Graphs{
		"connections": {
			Label: "Libreswan Total Connections",
			Unit:  "integer",
			Metrics: []mp.Metrics{
				{Name: "loaded", Label: "Loaded"},
				{Name: "active", Label: "Active"},
			},
		},
		"ike_sas": {
			Label: "Libreswan IKESAs",
			Unit:  "integer",
			Metrics: []mp.Metrics{
				{Name: "ike_total", Label: "Total"},
				{Name: "ike_half_open", Label: "Half-open", Stacked: true},
				{Name: "ike_open", Label: "Open", Stacked: true},
				{Name: "ike_authenticated", Label: "Authenticated", Stacked: true},
				{Name: "ike_anonymous", Label: "Anonymous", Stacked: true},
			},
		},
		"ipsec_sas": {
			Label: "Libreswan IPsec SAs",
			Unit:  "integer",
			Metrics: []mp.Metrics{
				{Name: "ipsec_total", Label: "Total"},
				{Name: "ipsec_authenticated", Label: "Authenticated", Stacked: true},
				{Name: "ipsec_anonymous", Label: "Anonymous", Stacked: true},
			},
		},
	}
}

func (p *Plugin) MetricKeyPrefix() string {
	return "libreswan"
}

func (p *Plugin) ExecIPsecStatus() (string, error) {
	args := slices.Concat(p.Command, []string{"status"})
	var (
		stdout bytes.Buffer
		stderr bytes.Buffer
	)
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%w: %s", err, stderr.String())
	}
	return stdout.String(), nil
}

type TotalConnections struct {
	Loaded int
	Active int
}

func getTotalConnectionsFromIPsecStatusOutput(output string) (*TotalConnections, error) {
	re := regexp.MustCompile(`Total IPsec connections: loaded (\d+), active (\d+)`)
	matches := re.FindStringSubmatch(output)
	if matches == nil {
		return nil, fmt.Errorf("'Total IPsec connections' line is not found in ipsec status output")
	}
	loaded, _ := strconv.Atoi(matches[1])
	active, _ := strconv.Atoi(matches[2])
	return &TotalConnections{
		Loaded: loaded,
		Active: active,
	}, nil
}

type IKESAs struct {
	Total         int
	HalfOpen      int
	Open          int
	Authenticated int
	Anonymous     int
}

func getIKESAsFromIPsecStatusOutput(output string) (*IKESAs, error) {
	re := regexp.MustCompile(`IKE SAs: total\((\d+)\), half-open\((\d+)\), open\((\d+)\), authenticated\((\d+)\), anonymous\((\d+)\)`)
	matches := re.FindStringSubmatch(output)
	if matches == nil {
		return nil, fmt.Errorf("'IKE SAs' line is not found in ipsec status output")
	}
	total, _ := strconv.Atoi(matches[1])
	halfOpen, _ := strconv.Atoi(matches[2])
	open, _ := strconv.Atoi(matches[3])
	authenticated, _ := strconv.Atoi(matches[4])
	anonymous, _ := strconv.Atoi(matches[5])

	return &IKESAs{
		Total:         total,
		HalfOpen:      halfOpen,
		Open:          open,
		Authenticated: authenticated,
		Anonymous:     anonymous,
	}, nil
}

type IPsecSAs struct {
	Total         int
	Authenticated int
	Anonymous     int
}

func getIPsecSAsFromIPsecStatusOutput(output string) (*IPsecSAs, error) {
	re := regexp.MustCompile(`IPsec SAs: total\((\d+)\), authenticated\((\d+)\), anonymous\((\d+)\)`)
	matches := re.FindStringSubmatch(output)
	if matches == nil {
		return nil, fmt.Errorf("'IPsec SAs' line is not found in ipsec status output")
	}
	total, _ := strconv.Atoi(matches[1])
	authenticated, _ := strconv.Atoi(matches[2])
	anonymous, _ := strconv.Atoi(matches[3])

	return &IPsecSAs{
		Total:         total,
		Authenticated: authenticated,
		Anonymous:     anonymous,
	}, nil
}
