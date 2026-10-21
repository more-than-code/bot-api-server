package catalog

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"path"
	"strconv"
	"strings"
)

const (
	restartUnless  = "unless-stopped"
	maxCommandArgs = 32
	maxArgBytes    = 4096
	maxPorts       = 16
	maxEnvSets     = 8
	maxSecretEnv   = 64
	maxVolumes     = 8
	maxFiles       = 16
	maxTargetBytes = 255
	minHealthy     = 5
	maxHealthy     = 600
	defaultHealthy = 30
	minTimeout     = 10
	maxTimeout     = 3600
	defaultTimeout = 600
	minMemory      = 16
	maxMemory      = 65536
	maxHealthArgs  = 32
	maxHealthArg   = 1024
	minHealthEvery = 5
	maxHealthEvery = 300
	defHealthEvery = 30
	minHealthWait  = 1
	maxHealthWait  = 60
	defHealthWait  = 5
	minHealthTries = 1
	maxHealthTries = 10
	defHealthTries = 3
	minHealthStart = 0
	maxHealthStart = 600
	defHealthStart = 0
	minLogMB       = 1
	maxLogMB       = 100
	minLogFiles    = 1
	maxLogFiles    = 10
	pullSlackSec   = 300
	taskSlackSec   = 60
	shortTaskSec   = 60
)

// imageUserRe is the account-name rule. Numeric ids are checked separately.
var imageUserRe = runAsRe

// Image is a normalised image entry spec. Empty command and entrypoint are
// nil. Env, SecretEnv, EnvSets, Ports, Volumes, and Files are non-nil.
// Healthcheck and Logging are nil when the spec omitted them.
type Image struct {
	Kind            string
	Image           string
	RegistryHost    string
	Command         []string
	Entrypoint      []string
	Ports           []Port
	Env             map[string]string
	EnvSets         []string
	SecretEnv       map[string]string
	Volumes         []Volume
	Files           []FileMount
	Healthcheck     *Healthcheck
	Logging         *LogLimit
	Restart         string
	User            string
	HealthyAfterSec int
	MemoryMB        *int
	TimeoutSec      int
}

// Healthcheck is a Docker CMD healthcheck. Numbers are filled in at write time.
type Healthcheck struct {
	Test           []string `json:"test"`
	IntervalSec    int      `json:"interval_sec"`
	TimeoutSec     int      `json:"timeout_sec"`
	Retries        int      `json:"retries"`
	StartPeriodSec int      `json:"start_period_sec"`
}

// LogLimit is the optional json-file cap. Both numbers are required together.
type LogLimit struct {
	MaxSizeMB int `json:"max_size_mb"`
	MaxFiles  int `json:"max_files"`
}

// Port is one published port.
type Port struct {
	Host      int  `json:"host"`
	Container int  `json:"container"`
	Public    bool `json:"public"`
}

// Volume is one named volume. Target is absolute.
type Volume struct {
	Name     string `json:"name"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only"`
}

// FileMount is one project file mounted read-only. Target is absolute.
// Content is not part of the spec.
type FileMount struct {
	File   string `json:"file"`
	Target string `json:"target"`
}

// SetKeys maps an env set name to its key names. Values are not included.
type SetKeys map[string][]string

// ValidImageName is the catalog name rule plus the image suffix rule.
func ValidImageName(name string) bool {
	if !ValidName(name) {
		return false
	}
	return !strings.HasSuffix(name, "-") && !strings.HasSuffix(name, "-prev")
}

// BuildImage applies v1.8 writing rules 1–11, v1.9 rule 13, and v1.14 logging.
// sets is the project's env-set key names. files is the project's file names.
// A nil files map rejects every named file. Errors name a field and do not
// include image references, commands, env values, volume targets, file
// targets, users, or set names.
func BuildImage(name string, raw []byte, sets SetKeys, files map[string]struct{}) (Image, error) {
	if !ValidImageName(name) {
		return Image{}, fieldErr("invalid name")
	}
	fields, err := specFields(raw)
	if err != nil {
		return Image{}, err
	}
	kind, err := decodeString(fields, "kind")
	if err != nil {
		return Image{}, err
	}
	if kind != "service" && kind != "job" {
		return Image{}, fieldErr("invalid kind")
	}
	hc, err := decodeHealthcheck(fields["healthcheck"], kind)
	if err != nil {
		return Image{}, err
	}
	logging, err := decodeLogging(fields["logging"])
	if err != nil {
		return Image{}, err
	}
	refRaw, err := decodeString(fields, "image")
	if err != nil {
		return Image{}, fieldErr("invalid image")
	}
	ref, err := ParseImageRef(refRaw)
	if err != nil {
		return Image{}, err
	}
	command, err := decodeArgv(fields, "command")
	if err != nil {
		return Image{}, err
	}
	entrypoint, err := decodeArgv(fields, "entrypoint")
	if err != nil {
		return Image{}, err
	}
	ports, err := decodePorts(fields["ports"])
	if err != nil {
		return Image{}, err
	}
	env, err := decodeStringMap(fields, "env")
	if err != nil {
		return Image{}, fieldErr("invalid env")
	}
	if err := validateEnv(env); err != nil {
		return Image{}, err
	}
	envSets, err := decodeNameList(fields, "env_sets")
	if err != nil {
		return Image{}, err
	}
	if len(envSets) > maxEnvSets {
		return Image{}, fieldErr("invalid env_sets")
	}
	seenSet := map[string]bool{}
	for _, set := range envSets {
		if !ValidName(set) || seenSet[set] {
			return Image{}, fieldErr("invalid env_sets")
		}
		seenSet[set] = true
		if _, ok := sets[set]; !ok {
			return Image{}, fieldErr("unknown env set")
		}
	}
	secretEnv, err := decodeStringMap(fields, "secret_env")
	if err != nil {
		return Image{}, fieldErr("invalid secret_env")
	}
	if len(secretEnv) > maxSecretEnv {
		return Image{}, fieldErr("invalid secret_env")
	}
	if err := validateSecretEnv(secretEnv, sets); err != nil {
		return Image{}, err
	}
	volumes, err := decodeVolumes(fields["volumes"])
	if err != nil {
		return Image{}, err
	}
	mounts, err := decodeFiles(fields["files"], files)
	if err != nil {
		return Image{}, err
	}
	if err := filesOverlapVolumes(mounts, volumes); err != nil {
		return Image{}, err
	}
	restart, restartSet, err := decodeOptionalString(fields, "restart")
	if err != nil {
		return Image{}, fieldErr("invalid restart")
	}
	if kind == "job" {
		restart = restartNo
	} else if !restartSet {
		restart = restartUnless
	} else if restart != restartNo && restart != restartOnFailure && restart != restartUnless {
		return Image{}, fieldErr("invalid restart")
	}
	user, _, err := decodeOptionalString(fields, "user")
	if err != nil {
		return Image{}, fieldErr("invalid user")
	}
	if err := validateUser(user); err != nil {
		return Image{}, err
	}
	healthy, healthySet, err := decodeOptionalInt(fields, "healthy_after_sec")
	if err != nil {
		return Image{}, err
	}
	timeout, timeoutSet, err := decodeOptionalInt(fields, "timeout_sec")
	if err != nil {
		return Image{}, err
	}
	if kind == "job" && healthySet {
		return Image{}, fieldErr("invalid healthy_after_sec")
	}
	if kind == "service" && timeoutSet {
		return Image{}, fieldErr("invalid timeout_sec")
	}
	if kind == "service" {
		if !healthySet {
			healthy = defaultHealthy
		} else if healthy < minHealthy || healthy > maxHealthy {
			return Image{}, fieldErr("invalid healthy_after_sec")
		}
		timeout = 0
	} else {
		if !timeoutSet {
			timeout = defaultTimeout
		} else if timeout < minTimeout || timeout > maxTimeout {
			return Image{}, fieldErr("invalid timeout_sec")
		}
		healthy = 0
	}
	memory, err := decodeMemory(fields["memory_mb"])
	if err != nil {
		return Image{}, err
	}
	if env == nil {
		env = map[string]string{}
	}
	if secretEnv == nil {
		secretEnv = map[string]string{}
	}
	if envSets == nil {
		envSets = []string{}
	}
	return Image{
		Kind:            kind,
		Image:           ref.Image,
		RegistryHost:    ref.Host,
		Command:         command,
		Entrypoint:      entrypoint,
		Ports:           ports,
		Env:             env,
		EnvSets:         envSets,
		SecretEnv:       secretEnv,
		Volumes:         volumes,
		Files:           mounts,
		Healthcheck:     hc,
		Logging:         logging,
		Restart:         restart,
		User:            user,
		HealthyAfterSec: healthy,
		MemoryMB:        memory,
		TimeoutSec:      timeout,
	}, nil
}

// ReferencesEnv reports whether a deploy must resolve an env set or secret_env.
func (img Image) ReferencesEnv() bool {
	return len(img.EnvSets) > 0 || len(img.SecretEnv) > 0
}

// DeployTimeoutSec is the image_deploy task timeout.
// A job uses timeout_sec. A service uses healthy_after_sec, or the
// healthcheck wait when that is longer.
func DeployTimeoutSec(img Image) int {
	if img.Kind == "job" {
		return pullSlackSec + img.TimeoutSec + taskSlackSec
	}
	return serviceTimeoutSec(img)
}

// RollbackTimeoutSec is the image_rollback task timeout.
// Jobs use the service formula, including a zero healthy_after_sec.
// Pull slack stays. A healthcheck uses the same wait as a service deploy.
func RollbackTimeoutSec(img Image) int {
	return serviceTimeoutSec(img)
}

// serviceTimeoutSec is pull slack, plus the longer of healthy_after_sec and
// the Docker healthcheck wait, plus task slack. No healthcheck keeps
// healthy_after_sec. The wait is start_period_sec + interval_sec × (retries + 1).
func serviceTimeoutSec(img Image) int {
	body := img.HealthyAfterSec
	if img.Healthcheck != nil {
		h := img.Healthcheck
		wait := h.StartPeriodSec + h.IntervalSec*(h.Retries+1)
		if wait > body {
			body = wait
		}
	}
	return pullSlackSec + body + taskSlackSec
}

// ShortTimeoutSec is the timeout for remove, start, stop, restart, status, and logs.
func ShortTimeoutSec() int {
	return shortTaskSec
}

// ReferencedSets is the sorted union of env_sets and secret_env set names.
func ReferencedSets(img Image) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(set string) {
		if set == "" {
			return
		}
		if _, ok := seen[set]; ok {
			return
		}
		seen[set] = struct{}{}
		out = append(out, set)
	}
	for _, set := range img.EnvSets {
		add(set)
	}
	for _, ref := range img.SecretEnv {
		set, _, _ := strings.Cut(ref, ".")
		add(set)
	}
	sortStrings(out)
	return out
}

// ReferencesSet reports whether the entry's hash depends on set.
func ReferencesSet(img Image, set string) bool {
	for _, name := range ReferencedSets(img) {
		if name == set {
			return true
		}
	}
	return false
}

// EnvKeyDigest is sha256 of the sorted key names joined by newlines.
// Values are not part of the digest. An empty list hashes the empty string.
func EnvKeyDigest(keys []string) string {
	cp := append([]string(nil), keys...)
	sortStrings(cp)
	sum := sha256.Sum256([]byte(strings.Join(cp, "\n")))
	return hex.EncodeToString(sum[:])
}

// ImageHash is the image spec_hash. keyDigests maps a referenced set to EnvKeyDigest.
// A missing digest is the empty-key digest. Values never enter the hash.
func ImageHash(img Image, keyDigests map[string]string) string {
	sum := sha256.Sum256([]byte(CanonicalImage(img, keyDigests)))
	return hex.EncodeToString(sum[:])
}

// CanonicalImage is the hash input: kind, spec, and env_keys, sorted keys, no whitespace.
func CanonicalImage(img Image, keyDigests map[string]string) string {
	sets := ReferencedSets(img)
	var ek strings.Builder
	ek.WriteByte('{')
	for i, set := range sets {
		if i > 0 {
			ek.WriteByte(',')
		}
		d := ""
		if keyDigests != nil {
			d = keyDigests[set]
		}
		if d == "" {
			d = EnvKeyDigest(nil)
		}
		ek.WriteString(jsonString(set))
		ek.WriteByte(':')
		ek.WriteString(jsonString(d))
	}
	ek.WriteByte('}')
	return `{"env_keys":` + ek.String() + `,"kind":"image","spec":` + hashSpecJSON(img) + `}`
}

// SpecJSON is the stored ImageSpec object. An empty files list is [].
func SpecJSON(img Image) string {
	return specJSON(img, true)
}

// hashSpecJSON is the spec_hash input. An empty files list is omitted so the
// hash matches a wave 2a entry that had no files field.
func hashSpecJSON(img Image) string {
	return specJSON(img, len(img.Files) > 0)
}

func specJSON(img Image, withFiles bool) string {
	mem := "null"
	if img.MemoryMB != nil {
		mem = strconv.Itoa(*img.MemoryMB)
	}
	files := ""
	if withFiles {
		files = `,"files":` + filesJSON(img.Files)
	}
	hc := ""
	if img.Healthcheck != nil {
		hc = `,"healthcheck":` + healthcheckJSON(*img.Healthcheck)
	}
	logging := ""
	if img.Logging != nil {
		logging = `,"logging":` + loggingJSON(*img.Logging)
	}
	return `{"command":` + argvJSON(img.Command) +
		`,"entrypoint":` + argvJSON(img.Entrypoint) +
		`,"env":` + stringMapJSON(img.Env) +
		`,"env_sets":` + stringArrayJSON(img.EnvSets) +
		files +
		hc +
		`,"healthy_after_sec":` + strconv.Itoa(img.HealthyAfterSec) +
		`,"image":` + jsonString(img.Image) +
		`,"kind":` + jsonString(img.Kind) +
		logging +
		`,"memory_mb":` + mem +
		`,"ports":` + portsJSON(img.Ports) +
		`,"restart":` + jsonString(img.Restart) +
		`,"secret_env":` + stringMapJSON(img.SecretEnv) +
		`,"timeout_sec":` + strconv.Itoa(img.TimeoutSec) +
		`,"user":` + jsonString(img.User) +
		`,"volumes":` + volumesJSON(img.Volumes) + `}`
}

// ParseStored reads a stored ImageSpec. It does not re-check env sets.
func ParseStored(raw []byte) (Image, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var doc storedImage
	if err := dec.Decode(&doc); err != nil {
		return Image{}, fieldErr("invalid spec")
	}
	if err := dec.Decode(new(struct{})); err != io.EOF {
		return Image{}, fieldErr("invalid spec")
	}
	ref, err := ParseImageRef(doc.Image)
	if err != nil {
		return Image{}, err
	}
	img := Image{
		Kind:            doc.Kind,
		Image:           ref.Image,
		RegistryHost:    ref.Host,
		Command:         nilIfEmpty(doc.Command),
		Entrypoint:      nilIfEmpty(doc.Entrypoint),
		Ports:           doc.Ports,
		Env:             nonNilMap(doc.Env),
		EnvSets:         nonNilList(doc.EnvSets),
		SecretEnv:       nonNilMap(doc.SecretEnv),
		Volumes:         doc.Volumes,
		Files:           doc.Files,
		Healthcheck:     doc.Healthcheck,
		Logging:         doc.Logging,
		Restart:         doc.Restart,
		User:            doc.User,
		HealthyAfterSec: doc.HealthyAfterSec,
		MemoryMB:        doc.MemoryMB,
		TimeoutSec:      doc.TimeoutSec,
	}
	if img.Ports == nil {
		img.Ports = []Port{}
	}
	if img.Volumes == nil {
		img.Volumes = []Volume{}
	}
	if img.Files == nil {
		img.Files = []FileMount{}
	}
	return img, nil
}

type storedImage struct {
	Kind            string            `json:"kind"`
	Image           string            `json:"image"`
	Command         []string          `json:"command"`
	Entrypoint      []string          `json:"entrypoint"`
	Ports           []Port            `json:"ports"`
	Env             map[string]string `json:"env"`
	EnvSets         []string          `json:"env_sets"`
	SecretEnv       map[string]string `json:"secret_env"`
	Volumes         []Volume          `json:"volumes"`
	Files           []FileMount       `json:"files"`
	Healthcheck     *Healthcheck      `json:"healthcheck"`
	Logging         *LogLimit         `json:"logging"`
	Restart         string            `json:"restart"`
	User            string            `json:"user"`
	HealthyAfterSec int               `json:"healthy_after_sec"`
	MemoryMB        *int              `json:"memory_mb"`
	TimeoutSec      int               `json:"timeout_sec"`
}

func (p Port) MarshalJSON() ([]byte, error) {
	pub := "false"
	if p.Public {
		pub = "true"
	}
	ro := `{"container":` + strconv.Itoa(p.Container) + `,"host":` + strconv.Itoa(p.Host) + `,"public":` + pub + `}`
	return []byte(ro), nil
}

func (v Volume) MarshalJSON() ([]byte, error) {
	ro := "false"
	if v.ReadOnly {
		ro = "true"
	}
	return []byte(`{"name":` + jsonString(v.Name) + `,"read_only":` + ro + `,"target":` + jsonString(v.Target) + `}`), nil
}

func nilIfEmpty(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	return items
}

func nonNilMap(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

func nonNilList(items []string) []string {
	if items == nil {
		return []string{}
	}
	return items
}

func sortStrings(items []string) {
	for i := 1; i < len(items); i++ {
		j := i
		for j > 0 && items[j] < items[j-1] {
			items[j], items[j-1] = items[j-1], items[j]
			j--
		}
	}
}

var imageFields = map[string]struct{}{
	"kind": {}, "image": {}, "command": {}, "entrypoint": {}, "ports": {},
	"env": {}, "env_sets": {}, "secret_env": {}, "volumes": {}, "files": {}, "healthcheck": {}, "logging": {}, "restart": {},
	"user": {}, "healthy_after_sec": {}, "memory_mb": {}, "timeout_sec": {},
}

func specFields(raw []byte) (map[string]json.RawMessage, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, fieldErr("invalid spec")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	var fields map[string]json.RawMessage
	if err := dec.Decode(&fields); err != nil {
		return nil, fieldErr("invalid spec")
	}
	if err := dec.Decode(new(struct{})); err != io.EOF {
		return nil, fieldErr("invalid spec")
	}
	for k := range fields {
		if _, ok := imageFields[k]; !ok {
			return nil, fieldErr("invalid spec")
		}
	}
	return fields, nil
}

func decodeString(fields map[string]json.RawMessage, name string) (string, error) {
	raw, ok := fields[name]
	if !ok || string(raw) == "null" {
		return "", fieldErr("invalid " + name)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fieldErr("invalid " + name)
	}
	return s, nil
}

func decodeOptionalString(fields map[string]json.RawMessage, name string) (string, bool, error) {
	raw, ok := fields[name]
	if !ok || string(raw) == "null" {
		return "", false, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false, fieldErr("invalid " + name)
	}
	return s, true, nil
}

// decodeHealthcheck applies defaults and rejects a job before it inspects test.
// Errors name the field and do not include argv.
func decodeHealthcheck(raw json.RawMessage, kind string) (*Healthcheck, error) {
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return nil, nil
	}
	if kind == "job" {
		return nil, fieldErr("healthcheck applies to services")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	var obj map[string]json.RawMessage
	if err := dec.Decode(&obj); err != nil || obj == nil {
		return nil, fieldErr("invalid healthcheck")
	}
	if err := dec.Decode(new(struct{})); err != io.EOF {
		return nil, fieldErr("invalid healthcheck")
	}
	allowed := map[string]struct{}{
		"test": {}, "interval_sec": {}, "timeout_sec": {}, "retries": {}, "start_period_sec": {},
	}
	for key := range obj {
		if _, ok := allowed[key]; !ok {
			return nil, fieldErr("invalid healthcheck")
		}
	}
	test, err := decodeHealthTest(obj["test"])
	if err != nil {
		return nil, err
	}
	interval, err := decodeBoundedInt(obj["interval_sec"], "healthcheck.interval_sec", minHealthEvery, maxHealthEvery, defHealthEvery)
	if err != nil {
		return nil, err
	}
	timeout, err := decodeBoundedInt(obj["timeout_sec"], "healthcheck.timeout_sec", minHealthWait, maxHealthWait, defHealthWait)
	if err != nil {
		return nil, err
	}
	retries, err := decodeBoundedInt(obj["retries"], "healthcheck.retries", minHealthTries, maxHealthTries, defHealthTries)
	if err != nil {
		return nil, err
	}
	start, err := decodeBoundedInt(obj["start_period_sec"], "healthcheck.start_period_sec", minHealthStart, maxHealthStart, defHealthStart)
	if err != nil {
		return nil, err
	}
	if timeout >= interval {
		return nil, fieldErr("invalid healthcheck.timeout_sec")
	}
	return &Healthcheck{
		Test:           test,
		IntervalSec:    interval,
		TimeoutSec:     timeout,
		Retries:        retries,
		StartPeriodSec: start,
	}, nil
}

func decodeHealthTest(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, fieldErr("invalid healthcheck.test")
	}
	var items []string
	if err := json.Unmarshal(raw, &items); err != nil || len(items) < 1 || len(items) > maxHealthArgs {
		return nil, fieldErr("invalid healthcheck.test")
	}
	for _, item := range items {
		if len(item) < 1 || len(item) > maxHealthArg || strings.ContainsRune(item, 0) {
			return nil, fieldErr("invalid healthcheck.test")
		}
	}
	return items, nil
}

func decodeBoundedInt(raw json.RawMessage, name string, min, max, def int) (int, error) {
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return def, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var n json.Number
	if err := dec.Decode(&n); err != nil {
		return 0, fieldErr("invalid " + name)
	}
	if err := dec.Decode(new(struct{})); err != io.EOF {
		return 0, fieldErr("invalid " + name)
	}
	v, err := n.Int64()
	if err != nil || v < int64(min) || v > int64(max) {
		return 0, fieldErr("invalid " + name)
	}
	return int(v), nil
}

// decodeLogging accepts null as absent. A present object needs both integers.
// An unknown key names the object. A missing, non-integer, or out-of-range
// value names logging.max_size_mb or logging.max_files.
func decodeLogging(raw json.RawMessage) (*LogLimit, error) {
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return nil, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	var obj map[string]json.RawMessage
	if err := dec.Decode(&obj); err != nil || obj == nil {
		return nil, fieldErr("invalid logging")
	}
	if err := dec.Decode(new(struct{})); err != io.EOF {
		return nil, fieldErr("invalid logging")
	}
	allowed := map[string]struct{}{"max_size_mb": {}, "max_files": {}}
	for key := range obj {
		if _, ok := allowed[key]; !ok {
			return nil, fieldErr("invalid logging")
		}
	}
	size, err := decodeRequiredInt(obj["max_size_mb"], "logging.max_size_mb", minLogMB, maxLogMB)
	if err != nil {
		return nil, err
	}
	files, err := decodeRequiredInt(obj["max_files"], "logging.max_files", minLogFiles, maxLogFiles)
	if err != nil {
		return nil, err
	}
	return &LogLimit{MaxSizeMB: size, MaxFiles: files}, nil
}

func decodeRequiredInt(raw json.RawMessage, name string, min, max int) (int, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" || !jsonIntToken(trimmed) {
		return 0, fieldErr("invalid " + name)
	}
	return decodeBoundedInt(raw, name, min, max, 0)
}

// jsonIntToken is a JSON number token. A quoted string is not an integer.
func jsonIntToken(raw []byte) bool {
	if len(raw) > 0 && raw[0] == '-' {
		raw = raw[1:]
	}
	return len(raw) > 0 && raw[0] >= '0' && raw[0] <= '9'
}

func loggingJSON(l LogLimit) string {
	return `{"max_files":` + strconv.Itoa(l.MaxFiles) + `,"max_size_mb":` + strconv.Itoa(l.MaxSizeMB) + `}`
}

func healthcheckJSON(h Healthcheck) string {
	return `{"interval_sec":` + strconv.Itoa(h.IntervalSec) +
		`,"retries":` + strconv.Itoa(h.Retries) +
		`,"start_period_sec":` + strconv.Itoa(h.StartPeriodSec) +
		`,"test":` + argvJSON(h.Test) +
		`,"timeout_sec":` + strconv.Itoa(h.TimeoutSec) + `}`
}

func decodeArgv(fields map[string]json.RawMessage, name string) ([]string, error) {
	raw, ok := fields[name]
	if !ok || string(raw) == "null" {
		return nil, nil
	}
	var items []string
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fieldErr("invalid " + name)
	}
	if len(items) == 0 {
		return nil, nil
	}
	if len(items) > maxCommandArgs {
		return nil, fieldErr("invalid " + name)
	}
	for _, item := range items {
		if len(item) > maxArgBytes || strings.ContainsAny(item, "\n\r") || strings.ContainsRune(item, 0) {
			return nil, fieldErr("invalid " + name)
		}
	}
	return items, nil
}

func decodeStringMap(fields map[string]json.RawMessage, name string) (map[string]string, error) {
	raw, ok := fields[name]
	if !ok || string(raw) == "null" {
		return map[string]string{}, nil
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fieldErr("invalid " + name)
	}
	if m == nil {
		m = map[string]string{}
	}
	return m, nil
}

func decodeNameList(fields map[string]json.RawMessage, name string) ([]string, error) {
	raw, ok := fields[name]
	if !ok || string(raw) == "null" {
		return []string{}, nil
	}
	var items []string
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fieldErr("invalid " + name)
	}
	if items == nil {
		items = []string{}
	}
	return items, nil
}

func decodeOptionalInt(fields map[string]json.RawMessage, name string) (int, bool, error) {
	raw, ok := fields[name]
	if !ok || string(raw) == "null" {
		return 0, false, nil
	}
	var n int
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, false, fieldErr("invalid " + name)
	}
	return n, true, nil
}

func decodeMemory(raw json.RawMessage) (*int, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var n int
	if err := json.Unmarshal(raw, &n); err != nil || n < minMemory || n > maxMemory {
		return nil, fieldErr("invalid memory_mb")
	}
	return &n, nil
}

func decodePorts(raw json.RawMessage) ([]Port, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return []Port{}, nil
	}
	var items []portIn
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&items); err != nil {
		return nil, fieldErr("invalid ports")
	}
	if len(items) > maxPorts {
		return nil, fieldErr("invalid ports")
	}
	out := make([]Port, 0, len(items))
	hosts := map[int]struct{}{}
	for _, item := range items {
		if item.Host == nil || item.Container == nil {
			return nil, fieldErr("invalid ports")
		}
		if *item.Host < 1 || *item.Host > 65535 || *item.Container < 1 || *item.Container > 65535 {
			return nil, fieldErr("invalid ports")
		}
		if _, dup := hosts[*item.Host]; dup {
			return nil, fieldErr("invalid ports")
		}
		hosts[*item.Host] = struct{}{}
		pub := false
		if item.Public != nil {
			pub = *item.Public
		}
		out = append(out, Port{Host: *item.Host, Container: *item.Container, Public: pub})
	}
	return out, nil
}

type portIn struct {
	Host      *int  `json:"host"`
	Container *int  `json:"container"`
	Public    *bool `json:"public"`
}

func decodeVolumes(raw json.RawMessage) ([]Volume, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return []Volume{}, nil
	}
	var items []volumeIn
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&items); err != nil {
		return nil, fieldErr("invalid volumes")
	}
	if len(items) > maxVolumes {
		return nil, fieldErr("invalid volumes")
	}
	out := make([]Volume, 0, len(items))
	targets := map[string]struct{}{}
	for _, item := range items {
		if !ValidName(item.Name) {
			return nil, fieldErr("invalid volumes")
		}
		if !validTarget(item.Target) {
			return nil, fieldErr("invalid volumes")
		}
		if _, dup := targets[item.Target]; dup {
			return nil, fieldErr("invalid volumes")
		}
		targets[item.Target] = struct{}{}
		out = append(out, Volume{Name: item.Name, Target: item.Target, ReadOnly: item.ReadOnly})
	}
	return out, nil
}

type volumeIn struct {
	Name     string `json:"name"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only"`
}

func decodeFiles(raw json.RawMessage, known map[string]struct{}) ([]FileMount, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return []FileMount{}, nil
	}
	var items []fileIn
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&items); err != nil {
		return nil, fieldErr("invalid files")
	}
	if len(items) > maxFiles {
		return nil, fieldErr("invalid files")
	}
	out := make([]FileMount, 0, len(items))
	names := map[string]struct{}{}
	targets := map[string]struct{}{}
	for _, item := range items {
		if !ValidFileName(item.File) {
			return nil, fieldErr("invalid files")
		}
		if _, ok := known[item.File]; !ok {
			return nil, fieldErr("unknown file")
		}
		if !validFileTarget(item.Target) {
			return nil, fieldErr("invalid files")
		}
		if _, dup := names[item.File]; dup {
			return nil, fieldErr("invalid files")
		}
		if _, dup := targets[item.Target]; dup {
			return nil, fieldErr("invalid files")
		}
		names[item.File] = struct{}{}
		targets[item.Target] = struct{}{}
		out = append(out, FileMount{File: item.File, Target: item.Target})
	}
	return out, nil
}

type fileIn struct {
	File   string `json:"file"`
	Target string `json:"target"`
}

func validFileTarget(target string) bool {
	if target == "" || target == "/" || len(target) > maxTargetBytes {
		return false
	}
	if !strings.HasPrefix(target, "/") || strings.HasSuffix(target, "/") {
		return false
	}
	if strings.ContainsRune(target, 0) || strings.ContainsAny(target, "\n\r") {
		return false
	}
	parts := strings.Split(target, "/")
	if len(parts) < 2 || parts[0] != "" {
		return false
	}
	for _, seg := range parts[1:] {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	if target == "/proc" || strings.HasPrefix(target, "/proc/") {
		return false
	}
	if target == "/sys" || strings.HasPrefix(target, "/sys/") {
		return false
	}
	if target == "/dev" || strings.HasPrefix(target, "/dev/") {
		return false
	}
	return true
}

func filesOverlapVolumes(files []FileMount, volumes []Volume) error {
	for _, file := range files {
		for _, vol := range volumes {
			if targetsOverlap(file.Target, vol.Target) {
				return fieldErr("invalid files")
			}
		}
	}
	return nil
}

// targetsOverlap compares a file target with a volume target. Volume rule 8
// still accepts "/", a trailing slash, and empty segments; those are cleaned
// here so they cannot hide an overlap. A volume that cleans to "/" covers
// every file.
func targetsOverlap(fileTarget, volumeTarget string) bool {
	file := path.Clean(fileTarget)
	volume := path.Clean(volumeTarget)
	if volume == "/" {
		return true
	}
	if file == volume {
		return true
	}
	return strings.HasPrefix(file, volume+"/") || strings.HasPrefix(volume, file+"/")
}

func filesJSON(items []FileMount) string {
	if len(items) == 0 {
		return "[]"
	}
	var b strings.Builder
	b.WriteByte('[')
	for i, item := range items {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"file":` + jsonString(item.File) + `,"target":` + jsonString(item.Target) + `}`)
	}
	b.WriteByte(']')
	return b.String()
}

func validTarget(target string) bool {
	if target == "" || len(target) > maxTargetBytes || !strings.HasPrefix(target, "/") {
		return false
	}
	if strings.ContainsRune(target, 0) || strings.ContainsAny(target, "\n\r") {
		return false
	}
	for _, seg := range strings.Split(target, "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

func validateSecretEnv(env map[string]string, sets SetKeys) error {
	for key, ref := range env {
		if !envKeyRe.MatchString(key) {
			return fieldErr("invalid env key")
		}
		if key == "PATH" || key == "HOME" {
			return fieldErr(key + " is reserved")
		}
		if changesWhatRuns(key) {
			return fieldErr("this variable changes what the program runs")
		}
		set, inner, ok := strings.Cut(ref, ".")
		if !ok || !ValidName(set) || !envKeyRe.MatchString(inner) {
			return fieldErr("invalid secret_env")
		}
		keys, exists := sets[set]
		if !exists {
			return fieldErr("unknown env set")
		}
		found := false
		for _, have := range keys {
			if have == inner {
				found = true
				break
			}
		}
		if !found {
			return fieldErr("unknown env key")
		}
	}
	return nil
}

func validateUser(user string) error {
	if user == "" {
		return nil
	}
	if strings.ContainsAny(user, " \t\r\n") || strings.ContainsRune(user, 0) {
		return fieldErr("invalid user")
	}
	left, right, group := strings.Cut(user, ":")
	if strings.Contains(right, ":") {
		return fieldErr("invalid user")
	}
	if err := validateUserPart(left); err != nil {
		return err
	}
	if group {
		if right == "" {
			return fieldErr("invalid user")
		}
		if err := validateUserPart(right); err != nil {
			return err
		}
	}
	return nil
}

func validateUserPart(part string) error {
	if part == "" || part == "root" || part == "0" {
		return fieldErr("invalid user")
	}
	if imageUserRe.MatchString(part) {
		return nil
	}
	if part[0] == '0' {
		return fieldErr("invalid user")
	}
	n := 0
	for _, c := range part {
		if c < '0' || c > '9' {
			return fieldErr("invalid user")
		}
		n = n*10 + int(c-'0')
		if n > 1<<31-1 {
			return fieldErr("invalid user")
		}
	}
	if n < 1 {
		return fieldErr("invalid user")
	}
	return nil
}

func argvJSON(items []string) string {
	if len(items) == 0 {
		return "null"
	}
	return stringArrayJSON(items)
}

func stringArrayJSON(items []string) string {
	if len(items) == 0 {
		return "[]"
	}
	var b strings.Builder
	b.WriteByte('[')
	for i, s := range items {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(jsonString(s))
	}
	b.WriteByte(']')
	return b.String()
}

func stringMapJSON(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sortStrings(keys)
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(jsonString(k))
		b.WriteByte(':')
		b.WriteString(jsonString(m[k]))
	}
	b.WriteByte('}')
	return b.String()
}

func portsJSON(ports []Port) string {
	if len(ports) == 0 {
		return "[]"
	}
	var b strings.Builder
	b.WriteByte('[')
	for i, p := range ports {
		if i > 0 {
			b.WriteByte(',')
		}
		raw, _ := p.MarshalJSON()
		b.Write(raw)
	}
	b.WriteByte(']')
	return b.String()
}

func volumesJSON(volumes []Volume) string {
	if len(volumes) == 0 {
		return "[]"
	}
	var b strings.Builder
	b.WriteByte('[')
	for i, v := range volumes {
		if i > 0 {
			b.WriteByte(',')
		}
		raw, _ := v.MarshalJSON()
		b.Write(raw)
	}
	b.WriteByte(']')
	return b.String()
}
