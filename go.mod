// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

module github.com/openrundev/openrun

go 1.25.0

require (
	github.com/BurntSushi/toml v1.4.0
	github.com/Masterminds/sprig/v3 v3.3.0
	github.com/andybalholm/brotli v1.1.1
	github.com/aws/aws-sdk-go-v2 v1.32.6
	github.com/aws/aws-sdk-go-v2/config v1.28.6
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.34.7
	github.com/benbjohnson/hashfs v0.2.2
	github.com/fsnotify/fsnotify v1.8.0
	github.com/go-chi/chi v1.5.5
	github.com/go-git/go-git/v5 v5.13.1
	github.com/gorilla/sessions v1.4.0
	github.com/hashicorp/vault/api v1.15.0
	github.com/jackc/pgx/v5 v5.7.5
	github.com/jackc/pgxlisten v0.0.0-20241106001234-1d6f6656415c
	github.com/markbates/goth v1.80.0
	github.com/moby/buildkit v0.18.1
	github.com/pkg/profile v1.7.0
	github.com/rs/zerolog v1.33.0
	github.com/russellhaering/gosaml2 v0.10.0
	github.com/russellhaering/goxmldsig v1.5.0
	github.com/segmentio/ksuid v1.0.4
	github.com/urfave/cli/v2 v2.27.5
	go.starlark.net v0.0.0-20241125201518-c05ff208a98f
	golang.org/x/sync v0.13.0
	golang.org/x/term v0.31.0
	gopkg.in/natefinch/lumberjack.v2 v2.2.1
	modernc.org/sqlite v1.34.2
)

require (
	cloud.google.com/go/compute v1.29.0 // indirect
	cloud.google.com/go/compute/metadata v0.5.2 // indirect
	dario.cat/mergo v1.0.1 // indirect
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver/v3 v3.3.1 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/ProtonMail/go-crypto v1.1.3 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.17.47 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.21 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.25 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.25 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.12.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.12.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.24.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.28.6 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.33.2 // indirect
	github.com/aws/smithy-go v1.22.1 // indirect
	github.com/beevik/etree v1.5.0 // indirect
	github.com/caddyserver/zerossl v0.1.3 // indirect
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/cloudflare/circl v1.6.1 // indirect
	github.com/containerd/typeurl/v2 v2.2.3 // indirect
	github.com/cyphar/filepath-securejoin v0.3.6 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/emirpasic/gods v1.18.1 // indirect
	github.com/felixge/fgprof v0.9.5 // indirect
	github.com/go-git/gcfg v1.5.1-0.20230307220236-3a3c6141e376 // indirect
	github.com/go-git/go-billy/v5 v5.6.1 // indirect
	github.com/go-jose/go-jose/v4 v4.0.5 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/google/pprof v0.0.0-20241206021119-61a79c692802 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/mux v1.8.1 // indirect
	github.com/gorilla/securecookie v1.1.2 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.7 // indirect
	github.com/hashicorp/go-rootcerts v1.0.2 // indirect
	github.com/hashicorp/go-secure-stdlib/parseutil v0.1.8 // indirect
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2 // indirect
	github.com/hashicorp/go-sockaddr v1.0.7 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/huandu/xstrings v1.5.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/kevinburke/ssh_config v1.2.0 // indirect
	github.com/klauspost/cpuid/v2 v2.2.9 // indirect
	github.com/libdns/libdns v0.2.2 // indirect
	github.com/markbates/going v1.0.3 // indirect
	github.com/mattermost/xml-roundtrip-validator v0.1.0 // indirect
	github.com/mholt/acmez/v2 v2.0.3 // indirect
	github.com/miekg/dns v1.1.62 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/ncruces/go-strftime v0.1.9 // indirect
	github.com/pjbgf/sha1cd v0.3.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/planetscale/vtprotobuf v0.6.1-0.20240319094008-0393e58bdf10 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	github.com/sergi/go-diff v1.3.2-0.20230802210424-5b0b94c5c0d3 // indirect
	github.com/shopspring/decimal v1.4.0 // indirect
	github.com/skeema/knownhosts v1.3.0 // indirect
	github.com/spf13/cast v1.7.0 // indirect
	github.com/xanzy/ssh-agent v0.3.3 // indirect
	github.com/zeebo/blake3 v0.2.4 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	golang.org/x/exp v0.0.0-20241204233417-43b7b7cde48d // indirect
	golang.org/x/mod v0.22.0 // indirect
	golang.org/x/net v0.38.0 // indirect
	golang.org/x/oauth2 v0.27.0 // indirect
	golang.org/x/text v0.24.0 // indirect
	golang.org/x/time v0.8.0 // indirect
	golang.org/x/tools v0.28.0 // indirect
	google.golang.org/protobuf v1.35.2 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
	modernc.org/gc/v3 v3.0.0-20240107210532-573471604cb6 // indirect
	modernc.org/libc v1.61.4 // indirect
	modernc.org/mathutil v1.6.0 // indirect
	modernc.org/memory v1.8.0 // indirect
	modernc.org/strutil v1.2.0 // indirect
	modernc.org/token v1.1.0 // indirect
)

require (
	github.com/bmatcuk/doublestar/v4 v4.7.1
	github.com/caddyserver/certmagic v0.21.4
	github.com/cpuguy83/go-md2man/v2 v2.0.5 // indirect
	github.com/evanw/esbuild v0.24.0
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/xrash/smetrics v0.0.0-20240521201337-686a1a2994c1 // indirect
	golang.org/x/crypto v0.37.0
	golang.org/x/sys v0.32.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace cloud.google.com/go/compute/metadata => cloud.google.com/go/compute/metadata v0.2.3
