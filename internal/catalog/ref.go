package catalog

import (
	"regexp"
	"strconv"
	"strings"
)

const (
	dockerHub = "docker.io"
	// Stored image references are at most this many bytes.
	maxImageLen = 255
)

var (
	// nameComponent is the distribution reference path component.
	nameComponent = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|[-]*)[a-z0-9]+)*$`)
	tagRe         = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	digestRe      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	regHostRe     = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*(?::[0-9]{1,5})?$`)
)

// ImageRef is a normalised Docker reference.
type ImageRef struct {
	// Image is the stored form. A missing tag and digest become :latest.
	Image string
	// Host is the registry host, including a port. docker.io is explicit.
	Host string
}

// ParseImageRef normalises a Docker reference the way the agent does.
// The registry host is lowercased. docker.io and library/ are made explicit.
// An uppercase path is rejected. The error does not include the reference.
func ParseImageRef(raw string) (ImageRef, error) {
	if raw == "" || len(raw) > 512 || strings.ContainsAny(raw, " \t\r\n") || strings.ContainsRune(raw, 0) {
		return ImageRef{}, fieldErr("invalid image")
	}
	name := raw
	digest := ""
	if i := strings.IndexByte(name, '@'); i >= 0 {
		digest = name[i+1:]
		name = name[:i]
		if !digestRe.MatchString(digest) {
			return ImageRef{}, fieldErr("invalid image")
		}
	}
	tag := ""
	if i := strings.LastIndexByte(name, ':'); i >= 0 {
		if slash := strings.LastIndexByte(name, '/'); slash < i {
			tag = name[i+1:]
			name = name[:i]
			if !tagRe.MatchString(tag) {
				return ImageRef{}, fieldErr("invalid image")
			}
		}
	}
	if name == "" || strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/") || strings.Contains(name, "//") {
		return ImageRef{}, fieldErr("invalid image")
	}
	host, path := splitDockerDomain(name)
	host = strings.ToLower(host)
	if !ValidRegistryHost(host) {
		return ImageRef{}, fieldErr("invalid image")
	}
	parts := strings.Split(path, "/")
	if len(parts) == 0 {
		return ImageRef{}, fieldErr("invalid image")
	}
	for _, part := range parts {
		if !nameComponent.MatchString(part) {
			return ImageRef{}, fieldErr("invalid image")
		}
	}
	if host == dockerHub && len(parts) != 2 {
		return ImageRef{}, fieldErr("invalid image")
	}
	if tag == "" && digest == "" {
		tag = "latest"
	}
	stored := host + "/" + path
	if tag != "" {
		stored += ":" + tag
	}
	if digest != "" {
		stored += "@" + digest
	}
	if len(stored) > maxImageLen {
		return ImageRef{}, fieldErr("invalid image")
	}
	return ImageRef{Image: stored, Host: host}, nil
}

func splitDockerDomain(name string) (host, path string) {
	i := strings.IndexByte(name, '/')
	if i < 0 || (!strings.ContainsAny(name[:i], ".:") && !strings.EqualFold(name[:i], "localhost")) {
		host, path = dockerHub, name
	} else {
		host, path = name[:i], name[i+1:]
	}
	if strings.EqualFold(host, "index.docker.io") {
		host = dockerHub
	}
	if strings.EqualFold(host, dockerHub) && !strings.ContainsRune(path, '/') {
		path = "library/" + path
	}
	return host, path
}

// ValidRegistryHost reports whether host is a lowercase hostname with an
// optional port in 1..65535. No scheme, path, or userinfo.
func ValidRegistryHost(host string) bool {
	if host == "" || len(host) > 255 || !regHostRe.MatchString(host) {
		return false
	}
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		n, err := strconv.Atoi(host[i+1:])
		if err != nil || n < 1 || n > 65535 {
			return false
		}
	}
	return true
}

// ValidDigest reports whether digest is sha256 and 64 lowercase hex digits.
func ValidDigest(digest string) bool {
	return digestRe.MatchString(digest)
}
