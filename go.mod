module github.com/freifunkMUC/wg-access-server

go 1.26.0

require (
	connectrpc.com/connect v1.21.0
	github.com/alecthomas/kingpin/v2 v2.4.0
	github.com/coreos/go-iptables v0.8.0
	github.com/coreos/go-oidc/v3 v3.21.0
	github.com/freifunkMUC/pg-events v0.5.0
	github.com/freifunkMUC/wg-embed v0.11.0
	github.com/google/uuid v1.6.0
	github.com/gorilla/mux v1.8.1
	github.com/gorilla/sessions v1.4.0
	github.com/hashicorp/golang-lru/v2 v2.0.7
	github.com/miekg/dns v1.1.73
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.24.1
	github.com/sirupsen/logrus v1.10.2
	github.com/stretchr/testify v1.12.1
	github.com/tg123/go-htpasswd v1.2.5
	github.com/vishvananda/netlink v1.3.1
	golang.org/x/crypto v0.57.0
	golang.org/x/oauth2 v0.37.0
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20241231184526-a9ab2273dd10
	google.golang.org/protobuf v1.36.12
	gopkg.in/Knetic/govaluate.v2 v2.3.0
	gopkg.in/yaml.v2 v2.4.0
	gorm.io/driver/mysql v1.6.0
	gorm.io/driver/postgres v1.6.3
	gorm.io/driver/sqlite v1.6.0
	gorm.io/gorm v1.31.2
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/GehirnInc/crypt v0.0.0-20230320061759-8cc1b52080c5 // indirect
	github.com/alecthomas/units v0.0.0-20240927000941-0f3dac36c52b // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/go-jose/go-jose/v4 v4.1.5 // indirect
	github.com/go-sql-driver/mysql v1.10.1 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/gorilla/securecookie v1.1.2 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/pgx/v5 v5.10.0 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/lib/pq v1.12.3 // indirect
	github.com/mattn/go-sqlite3 v1.14.52 // indirect
	github.com/mdlayher/genetlink v1.4.0 // indirect
	github.com/mdlayher/netlink v1.11.2 // indirect
	github.com/mdlayher/socket v0.7.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_model v0.6.3 // indirect
	github.com/prometheus/common v0.71.0 // indirect
	github.com/prometheus/procfs v0.22.0 // indirect
	github.com/rogpeppe/go-internal v1.16.0 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	github.com/xhit/go-str2duration/v2 v2.1.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/net v0.59.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446 // indirect
	gopkg.in/ini.v1 v1.67.3 // indirect
)

tool (
	connectrpc.com/connect/cmd/protoc-gen-connect-go
	google.golang.org/protobuf/cmd/protoc-gen-go
)
