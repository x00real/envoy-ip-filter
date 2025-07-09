package main

import (
	"fmt"
	"net"

	net_http "net/http"

	xds "github.com/cncf/xds/go/xds/type/v3"
	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	"github.com/envoyproxy/envoy/contrib/golang/filters/http/source/go/pkg/http"
	"google.golang.org/protobuf/types/known/anypb"
)

const NAME = "x00real.ip_filter"

func init() {
	http.RegisterHttpFilterFactoryAndConfigParser(NAME, filterFactory, &parser{})
}

var CloudflareIpRanges = func() []*net.IPNet {
	ranges := []string{
		"173.245.48.0/20",
		"103.21.244.0/22",
		"103.22.200.0/22",
		"103.31.4.0/22",
		"141.101.64.0/18",
		"108.162.192.0/18",
		"190.93.240.0/20",
		"188.114.96.0/20",
		"197.234.240.0/22",
		"198.41.128.0/17",
		"162.158.0.0/15",
		"104.16.0.0/13",
		"104.24.0.0/14",
		"172.64.0.0/13",
		"131.0.72.0/22",
		"2400:cb00::/32",
		"2606:4700::/32",
		"2803:f800::/32",
		"2405:b500::/32",
		"2405:8100::/32",
		"2a06:98c0::/29",
		"2c0f:f248::/32",
	}

	ret := make([]*net.IPNet, 0, len(ranges))
	for _, r := range ranges {
		_, ipNet, err := net.ParseCIDR(r)
		if err != nil {
			panic(fmt.Sprintf("Invalid CIDR range: %s, error: %v", r, err))
		}
		ret = append(ret, ipNet)
	}
	return ret
}()

type parser struct{}

// Merge implements api.StreamFilterConfigParser.
func (p *parser) Merge(parentConfig any, childConfig any) any {
	parentCfg := parentConfig.(*Config)
	childCfg := childConfig.(*Config)

	filter := *parentCfg
	if childCfg.HeaderName != "" {
		filter.HeaderName = childCfg.HeaderName
	}
	if childCfg.CloudflareIpRanges != nil {
		filter.CloudflareIpRanges = childCfg.CloudflareIpRanges
	}
	if childCfg.IpCacheSize > 0 {
		filter.IpCacheSize = childCfg.IpCacheSize
	}
	return &filter
}

// Parse implements api.StreamFilterConfigParser.
func (p *parser) Parse(any *anypb.Any, callbacks api.ConfigCallbackHandler) (any, error) {
	cfg := &xds.TypedStruct{}
	if err := any.UnmarshalTo(cfg); err != nil {
		return nil, fmt.Errorf("unmarshaling config: %w", err)
	}

	values := cfg.GetValue().AsMap()

	config := Config{
		HeaderName:         DEFAULT_HEADER_NAME,
		CloudflareIpRanges: CloudflareIpRanges,
	}

	if header, ok := values["header_name"].(string); ok && header != "" {
		config.HeaderName = header
	}

	if fetch, ok := values["fetch_cloudflare_ip"].(bool); ok && fetch {
		var err error
		if config.CloudflareIpRanges, err = fetchCloudflareIpRanges(); err != nil {
			return nil, fmt.Errorf("fetching Cloudflare IP ranges: %w", err)
		}
	}

	if ipCacheSize, ok := values["ip_cache_size"].(uint32); ok && ipCacheSize > 0 {
		config.IpCacheSize = ipCacheSize
	}

	return &config, nil
}

func filterFactory(config any, callbacks api.FilterCallbackHandler) api.StreamFilter {
	cfg, ok := config.(*Config)
	if !ok {
		callbacks.Log(api.Error, "Invalid filter configuration type")
		panic(fmt.Sprintf("expected *Config, got %T", config))
	}
	return NewFilter(*cfg, callbacks)
}

func fetchCloudflareIpRanges() ([]*net.IPNet, error) {
	client := net_http.Client{}

	fetchRange := func(endpoint string) ([]*net.IPNet, error) {
		resp, err := client.Get(endpoint)
		if err != nil {
			return nil, fmt.Errorf("fetching Cloudflare IP ranges: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != net_http.StatusOK {
			return nil, fmt.Errorf("fetching Cloudflare IP ranges: received status code %d", resp.StatusCode)
		}

		var ranges []*net.IPNet
		for {
			var ipRange string
			_, err := fmt.Fscanln(resp.Body, &ipRange)
			if err != nil {
				break // EOF or error
			}

			_, ipNet, err := net.ParseCIDR(ipRange)
			if err != nil {
				return nil, fmt.Errorf("parsing Cloudflare IP range %s: %w", ipRange, err)
			}

			ranges = append(ranges, ipNet)
		}
		return ranges, nil
	}

	ranges, err := fetchRange("https://www.cloudflare.com/ips-v4")
	if err != nil {
		return nil, fmt.Errorf("fetching IPv4 ranges: %w", err)
	}

	rangesV6, err := fetchRange("https://www.cloudflare.com/ips-v6")
	if err != nil {
		return nil, fmt.Errorf("fetching IPv6 ranges: %w", err)
	}
	return append(ranges, rangesV6...), nil
}
