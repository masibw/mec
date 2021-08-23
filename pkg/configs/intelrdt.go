package configs

type IntelRdt struct {
	L3CacheSchema string `json:"l3_cache_schema,omitempty"`
	MemBwSchema string `json:"memBwSchema,omitempty"`
}