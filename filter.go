package main

import (
	"fmt"
	"net"

	"github.com/envoyproxy/envoy/contrib/golang/common/go/api"
	lru "github.com/hashicorp/golang-lru/v2"
)

const (
	DEFAULT_HEADER_NAME    = "x-client-ip"
	CLOUDFLARE_HEADER_NAME = "cf-connecting-ip"
)

type Config struct {
	HeaderName         string
	CloudflareIpRanges []*net.IPNet
	IpCacheSize        uint32
}

type Filter struct {
	callbacks          api.FilterCallbackHandler
	ipCache            *lru.Cache[string, net.IP]
	headerName         string
	cloudflareIpRanges []*net.IPNet
}

var _ api.StreamFilter = (*Filter)(nil)

func NewFilter(cfg Config, callbacks api.FilterCallbackHandler) *Filter {
	filter := &Filter{
		headerName:         cfg.HeaderName,
		cloudflareIpRanges: cfg.CloudflareIpRanges,
		callbacks:          callbacks,
	}

	if cfg.IpCacheSize > 0 {
		filter.ipCache, _ = lru.New[string, net.IP](int(cfg.IpCacheSize))
	}
	return filter
}

// DecodeData implements api.StreamDecoderFilter.
func (f *Filter) DecodeData(api.BufferInstance, bool) api.StatusType {
	return api.Continue
}

// DecodeHeaders implements api.StreamDecoderFilter.
func (f *Filter) DecodeHeaders(requestHeader api.RequestHeaderMap, _ bool) api.StatusType {
	downstreamIp := f.getDownstreamIp()
	cfipRaw, found := requestHeader.Get(CLOUDFLARE_HEADER_NAME)

	// If the cloudflare ip header is not present, we just need set the header
	// to the downstream ip.
	if !found {
		requestHeader.Set(f.headerName, downstreamIp.String())
		return api.Continue
	}

	// If the cloudflare ip header is present, we need to parse it and
	// check if it is a valid IP address and must be in the cloudflare IP ranges.
	cfip, _ := f.getOrParseIp(cfipRaw)
	if cfip == nil || !f.isCloudflareIp(cfip) {
		f.callbacks.Log(api.Warn, fmt.Sprintf("Invalid ip address or not in cloudflare IP ranges: %s", cfipRaw))
		// If the cloudflare IP is invalid, we just set the header to the downstream IP.
		requestHeader.Set(f.headerName, downstreamIp.String())
		return api.Continue
	}

	// If the cloudflare IP is valid, we set the header to the cloudflare IP.
	requestHeader.Set(f.headerName, cfip.String())
	return api.Continue
}

// DecodeTrailers implements api.StreamDecoderFilter.
func (f *Filter) DecodeTrailers(api.RequestTrailerMap) api.StatusType {
	return api.Continue
}

// EncodeData implements api.StreamEncoderFilter.
func (f *Filter) EncodeData(api.BufferInstance, bool) api.StatusType {
	return api.Continue
}

// EncodeHeaders implements api.StreamEncoderFilter.
func (f *Filter) EncodeHeaders(api.ResponseHeaderMap, bool) api.StatusType {
	return api.Continue
}

// EncodeTrailers implements api.StreamEncoderFilter.
func (f *Filter) EncodeTrailers(api.ResponseTrailerMap) api.StatusType {
	return api.Continue
}

// OnDestroy implements api.StreamFilter.
func (f *Filter) OnDestroy(api.DestroyReason) {}

// OnLog implements api.StreamFilter.
func (f *Filter) OnLog(api.RequestHeaderMap, api.RequestTrailerMap, api.ResponseHeaderMap, api.ResponseTrailerMap) {
}

// OnLogDownstreamPeriodic implements api.StreamFilter.
func (f *Filter) OnLogDownstreamPeriodic(api.RequestHeaderMap, api.RequestTrailerMap, api.ResponseHeaderMap, api.ResponseTrailerMap) {
}

// OnLogDownstreamStart implements api.StreamFilter.
func (f *Filter) OnLogDownstreamStart(api.RequestHeaderMap) {}

// OnStreamComplete implements api.StreamFilter.
func (f *Filter) OnStreamComplete() {}

func (f *Filter) getDownstreamIp() net.IP {
	downstreamRaw := f.callbacks.StreamInfo().DownstreamRemoteAddress()
	ip, _ := f.getOrParseIp(downstreamRaw)
	if ip == nil {
		f.callbacks.Log(api.Error, fmt.Sprintf("Failed to parse downstream remote address: %s", downstreamRaw))
	}

	return ip
}

// getOrParseIp retrieves the IP from the cache if available, otherwise parses it.
// This function return the IP and a boolean indicating whether the IP was found in the cache.
func (f *Filter) getOrParseIp(raw string) (net.IP, bool) {
	raw, _, err := net.SplitHostPort(raw)
	if err != nil {
		f.callbacks.Log(api.Error, fmt.Sprintf("Failed to split host and port from address: %s, error: %v", raw, err))
		return nil, false
	}

	if f.ipCache != nil {
		var ip net.IP
		if ip, _ = f.ipCache.Get(raw); ip != nil {
			return ip, true
		}
		if ip = net.ParseIP(raw); ip == nil {
			f.ipCache.Add(raw, ip)
		}
		return ip, false
	}
	return net.ParseIP(raw), false
}

func (f *Filter) isCloudflareIp(ip net.IP) bool {
	if f.cloudflareIpRanges == nil {
		return false
	}
	for _, cidr := range f.cloudflareIpRanges {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}
