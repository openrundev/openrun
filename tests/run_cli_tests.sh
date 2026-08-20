#!/usr/bin/env bash
#set -x
set -eE

# Enabling verbose is useful for debugging but the commander command seems to
# return exit code of 0 when verbose is enabled, even if tests fails. So verbose
# is disabled by default.

usage() {
  cat <<'USAGE'
Usage: tests/run_cli_tests.sh [options] [test-file ...]

Runs the OpenRun CLI e2e test suite (commander-based). With no test-file
arguments the entire suite runs; otherwise only the named suites run (e.g.
test_reload.yaml, test_certs.yaml, test_containers.yaml) and any setup phase
that none of the requested files need (building test containers, starting
the Kubernetes suite, etc.) is skipped for speed.

All ports used are picked at random per invocation, so multiple invocations
against different --home directories can run at the same time on one
machine without colliding.

General:
  --home DIR              OPENRUN_HOME, the repo checkout to build/test
                           (default: parent directory of this script)
  --coverdir DIR           GOCOVERDIR for coverage-instrumented binaries
  --skip-build             Reuse the existing tests/../openrun binary instead
                           of rebuilding it (faster edit/run loops)
  --verbose                Pass --verbose to commander
  --dr                     Also run the disaster recovery scenarios in a full
                           run (they are skipped by default: slow, hard-kill a
                           server). The docker scenario needs --seaweedfs and a
                           container command; the kubernetes scenario needs
                           --seaweedfs and --kube-registry
  -h, --help               Show this help

Containers:
  --container-commands LIST  Space separated container commands to build/run
                              test apps with (default: "docker";
                              "disable" to skip container app tests)
  --container-tool CMD        Tool used for the Postgres/MySQL/forward-auth
                               test containers themselves (default: docker)
  --postgres                  Start a Postgres test container for suites that
                               need one
  --postgres-url URL           Use an already-running Postgres instead of
                               starting a container (implies --postgres)
  --mysql                      Start a MySQL test container for suites that
                               need one
  --mysql-url URL               Use an already-running MySQL instead of
                               starting a container (implies --mysql)
  --redis                      Start a Redis test container for suites that
                               need one (set OPENRUN_TEST_REDIS_IMAGE to e.g.
                               valkey/valkey:8-alpine to test against Valkey)
  --redis-url URL               Use an already-running Redis/Valkey instead of
                               starting a container (implies --redis)
  --seaweedfs                  Start a SeaweedFS test container (S3 API) for
                               the litestream replication suites
  --s3-url URL                  Use an already-running S3-compatible endpoint
                               instead (implies --seaweedfs); requires
                               TEST_S3_BUCKET, TEST_S3_ACCESS_KEY and
                               TEST_S3_SECRET_KEY to be set in the environment

Kubernetes (only runs when --kube-registry is set):
  --kube-registry URL      Container registry the Kubernetes suite pushes to
  --kube-namespace NAME     Namespace to use (default: openrun-cli-test-$$)
  --kube-s3-endpoint URL    S3 endpoint as reachable FROM CLUSTER PODS, for the
                             kubernetes disaster recovery scenario (default:
                             the SeaweedFS port on the --kube-registry host)

Git auth secrets stay as environment variables, not flags, so they don't show
up in the process list:
  CL_INFOCLACE_SSH   ssh private key contents, enables test_github_auth.yaml
  CL_GITHUB_SECRET   github oauth app secret, enables test_oauth.yaml
  TEST_PAT           personal access token used by the git ssh auth test
USAGE
}

HOME_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COVERDIR=""
SKIP_BUILD=""
VERBOSE=""
ENABLE_DR=""
CONTAINER_COMMANDS="docker"
CONTAINER_TOOL="docker"
ENABLE_POSTGRES=""
ENABLE_MYSQL=""
ENABLE_REDIS=""
ENABLE_SEAWEEDFS=""
POSTGRES_URL_ARG=""
MYSQL_URL_ARG=""
REDIS_URL_ARG=""
S3_URL_ARG=""
KUBE_REGISTRY_URL=""
KUBE_TEST_NAMESPACE=""
KUBE_S3_ENDPOINT_ARG=""
SEAWEEDFS_TEST_CONTAINER_ID=""
FORWARD_AUTH_CONTAINER_ID=""
FORWARD_AUTH_CONTAINER_COMMAND=""
POSTGRES_TEST_CONTAINER_ID=""
MYSQL_TEST_CONTAINER_ID=""
REDIS_TEST_CONTAINER_ID=""
SERVER_PID=""
DR_SERVER_PID=""
DR_HOME1=""
DR_HOME2=""
DR_KUBE_NS1=""
DR_KUBE_NS2=""
CLEANUP_DONE=""
# Directly-started helper containers get a per-invocation label. App and
# Litestream containers already carry dev.openrun.server.home.
TEST_SESSION_ID="openrun-cli-tests-$$-$RANDOM"
SEAWEEDFS_TEST_CONTAINER_NAME="$TEST_SESSION_ID-seaweedfs"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --home) HOME_DIR="$2"; shift 2 ;;
    --coverdir) COVERDIR="$2"; shift 2 ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    --verbose) VERBOSE="--verbose"; shift ;;
    --dr) ENABLE_DR=1; shift ;;
    --container-commands) CONTAINER_COMMANDS="$2"; shift 2 ;;
    --container-tool) CONTAINER_TOOL="$2"; shift 2 ;;
    --postgres) ENABLE_POSTGRES=1; shift ;;
    --postgres-url) ENABLE_POSTGRES=1; POSTGRES_URL_ARG="$2"; shift 2 ;;
    --mysql) ENABLE_MYSQL=1; shift ;;
    --mysql-url) ENABLE_MYSQL=1; MYSQL_URL_ARG="$2"; shift 2 ;;
    --redis) ENABLE_REDIS=1; shift ;;
    --redis-url) ENABLE_REDIS=1; REDIS_URL_ARG="$2"; shift 2 ;;
    --seaweedfs) ENABLE_SEAWEEDFS=1; shift ;;
    --s3-url) ENABLE_SEAWEEDFS=1; S3_URL_ARG="$2"; shift 2 ;;
    --kube-registry) KUBE_REGISTRY_URL="$2"; shift 2 ;;
    --kube-namespace) KUBE_TEST_NAMESPACE="$2"; shift 2 ;;
    --kube-s3-endpoint) KUBE_S3_ENDPOINT_ARG="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    -*) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
    *) break ;;
  esac
done
TESTS=("$@")
MATCHED_TESTS=()
TEST_CONTAINER_RUNTIMES="$CONTAINER_COMMANDS"

# is_selected NAME: true if no test-file args were given (run everything) or
# NAME is one of them.
is_selected() {
  if [[ ${#TESTS[@]} -eq 0 ]]; then
    return 0
  fi
  local t
  for t in "${TESTS[@]}"; do
    [[ "$t" == "$1" ]] && return 0
  done
  return 1
}

# is_explicitly_selected NAME: true only if NAME was passed as a test-file
# argument. Never true for full runs: used for suites that are disabled by
# default (e.g. the disaster recovery scenario).
is_explicitly_selected() {
  if [[ ${#TESTS[@]} -eq 0 ]]; then
    return 1
  fi
  local t
  for t in "${TESTS[@]}"; do
    [[ "$t" == "$1" ]] && return 0
  done
  return 1
}

# dr_selected NAME: the disaster recovery suites are skipped in default full
# runs (slow, hard-kill a server). They run when requested by name, or as part
# of a full run with --dr (e.g. the weekly verify job).
dr_selected() {
  if [[ -n "$ENABLE_DR" && ${#TESTS[@]} -eq 0 ]]; then
    return 0
  fi
  is_explicitly_selected "$1"
}

# contains_any "a b c": true if no test-file args were given or one of them
# matches a name in the given space separated list.
contains_any() {
  if [[ ${#TESTS[@]} -eq 0 ]]; then
    return 0
  fi
  local candidates=($1) t c
  for t in "${TESTS[@]}"; do
    for c in "${candidates[@]}"; do
      [[ "$t" == "$c" ]] && return 0
    done
  done
  return 1
}

cd "$HOME_DIR"
export GOCOVERDIR="$COVERDIR"

if [[ -n "$SKIP_BUILD" ]]; then
  echo "Skipping build, reusing existing ./openrun binary"
else
  # Setup app specs
  rm -rf appspecs_bk
  if [[ -d internal/server/appspecs/dummy ]]; then
    mv internal/server/appspecs appspecs_bk
    cp -r config/appspecs internal/server/
  fi

  if [[ -n "$GOCOVERDIR" ]]; then
      # atomic, not the default set: covtest merges this binary's coverage
      # data with the unit test data, which is atomic mode (covunit runs with
      # -race), and covdata rejects mixed counter modes
      go build -cover -covermode=atomic ./cmd/openrun
  else
      go build ./cmd/openrun
  fi

  if [[ -d appspecs_bk ]]; then
      # Restore appspecs
      rm -rf internal/server/appspecs
      mv appspecs_bk internal/server/appspecs
  fi
fi

cd tests
rm -rf metadata

export OPENRUN_HOME=.
TEST_SERVER_HOMES=("$(pwd -P)")
unset CL_CONFIG_FILE
unset SSH_AUTH_SOCK

# port_free checks whether something is already listening on 127.0.0.1:PORT.
port_free() {
  ! (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
}

# wait_port_free waits for PORT to be released — the previous server (or the
# forward-auth container) can take a moment to shut down after `server stop`
# returns — and fails with a clear error if the port stays occupied.
wait_port_free() {
  local port="$1" attempt
  for attempt in {1..100}; do
    if port_free "$port"; then
      return 0
    fi
    sleep 0.1
  done
  echo "Port $port is still in use, cannot start the next server" >&2
  return 1
}

# pick_port_base finds a random block of ports where every port this script
# will listen on (http, https, forward auth) is currently free, so concurrent
# invocations of this script (e.g. from different --home worktrees) or
# unrelated processes on the host don't fight over the same TCP ports. The
# block is regenerated (not just retried) on any hit. The range stays below
# 32768: ports inside the OS ephemeral range (Linux 32768+, macOS 49152+) can
# be grabbed as the local port of an unrelated OUTBOUND connection at any
# moment — port_free cannot see those (a connect test only detects listeners),
# and a later bind (e.g. docker-proxy publishing the forward-auth port) fails
# with "address already in use".
pick_port_base() {
  local base attempt
  for attempt in {1..30}; do
    base=$(( 20000 + (RANDOM % 127) * 100 ))
    if port_free "$base" && port_free "$((base + 1))" && port_free "$((base + 2))"; then
      echo "$base"
      return 0
    fi
  done
  echo "Could not find a free block of ports after 30 attempts" >&2
  return 1
}

PORT_BASE=$(pick_port_base)
# Every server in this script runs sequentially — each block stops its server
# before the next starts — so they all reuse one HTTP/HTTPS port pair; the
# forward-auth test container is the only additional listener that runs
# concurrently with a server. Using just three ports keeps the odds of
# colliding with an unrelated process low; every port is verified free at
# selection (pick_port_base) and again right before each bind
# (wait_port_free, which also absorbs the previous server's shutdown lag).
SERVER_HTTP_PORT=$((PORT_BASE))
SERVER_HTTPS_PORT=$((PORT_BASE + 1))
FORWARD_AUTH_PORT=$((PORT_BASE + 2))
# Names the test yaml env maps use for the shared pair
MAIN_HTTP_PORT=$SERVER_HTTP_PORT
MAIN_HTTPS_PORT=$SERVER_HTTPS_PORT
BASIC_HTTP_PORT=$SERVER_HTTP_PORT
BASIC_HTTPS_PORT=$SERVER_HTTPS_PORT
export MAIN_HTTP_PORT MAIN_HTTPS_PORT BASIC_HTTP_PORT BASIC_HTTPS_PORT
echo "Using ports http=$SERVER_HTTP_PORT https=$SERVER_HTTPS_PORT forward_auth=$FORWARD_AUTH_PORT"

# wait_for_http polls localhost:PORT until the server accepts HTTP connections
# or up to 10 seconds, replacing the fixed `sleep 2` guards after server start.
wait_for_http() {
  local port="$1"
  local max_attempts=100
  local attempt=0
  while [[ $attempt -lt $max_attempts ]]; do
    if curl -sS --connect-timeout 0.1 --max-time 0.5 -o /dev/null "http://127.0.0.1:${port}/" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
    attempt=$((attempt + 1))
  done
  echo "Timed out waiting for HTTP server on port ${port}" >&2
  return 1
}

# wait_for_socket polls the server's unix socket until it accepts connections.
# The CLI connects over run/openrun.sock when the client config has no
# server_uri; the socket listener can come up slightly after the TCP listener
# that wait_for_http checks, and on a loaded machine the first CLI call of a
# test suite can land in that gap and fail with connection refused.
# start_dr_server HOME CONFIG: start a server for the disaster recovery
# scenarios in its own OPENRUN_HOME (the socket lives under it, unlike the
# other phases which use the tests directory)
start_dr_server() {
  wait_port_free "$SERVER_HTTP_PORT" && wait_port_free "$SERVER_HTTPS_PORT"
  TEST_SERVER_HOMES+=("$1")
  OPENRUN_HOME="$1" CL_CONFIG_FILE="$2" GOCOVERDIR=$GOCOVERDIR ../openrun server start &
  DR_SERVER_PID=$!
  wait_for_http "$SERVER_HTTP_PORT"
  local attempt=0
  while [[ $attempt -lt 100 ]]; do
    if curl -sS --connect-timeout 0.1 --max-time 0.5 --unix-socket "$1/run/openrun.sock" -o /dev/null "http://openrun/" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
    attempt=$((attempt + 1))
  done
  echo "DR server socket did not become ready in $1"
  return 1
}

wait_for_socket() {
  local max_attempts=100
  local attempt=0
  while [[ $attempt -lt $max_attempts ]]; do
    if curl -sS --connect-timeout 0.1 --max-time 0.5 --unix-socket run/openrun.sock -o /dev/null "http://openrun/" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
    attempt=$((attempt + 1))
  done
  echo "Timed out waiting for unix socket run/openrun.sock" >&2
  return 1
}

error_handler () {
    echo "Error occurred, running cleanup"
    cleanup
    echo "Test failed"
    exit 1
}

# Containerized apps bind-mount their source dir and run as root, so they can
# leave root-owned files in the workspace (e.g. flaskapp/__pycache__,
# streamlitdev/.streamlit). Plain rm fails on those for a non-root user; retry
# survivors as root from inside a container. Never fails, so cleanup does not
# trip the ERR trap.
force_rm() {
  rm -rf "$@" 2>/dev/null || true
  local survivors=() p
  for p in "$@"; do
    [[ -e "$p" ]] && survivors+=("$p")
  done
  [[ ${#survivors[@]} -eq 0 ]] && return 0
  if command -v "$CONTAINER_TOOL" >/dev/null 2>&1; then
    $CONTAINER_TOOL run --rm \
      --label "dev.openrun.test.session=$TEST_SESSION_ID" \
      -v "$PWD":/w -w /w busybox rm -rf "${survivors[@]}" >/dev/null 2>&1 || true
  fi
  for p in "${survivors[@]}"; do
    [[ -e "$p" ]] && echo "Warning: cleanup could not remove: $p"
  done
  return 0
}

# remove_session_containers removes helper containers carrying this
# invocation's unique label and OpenRun-managed app/sidecar containers owned
# by any OPENRUN_HOME used during the invocation. Container engines are
# deduplicated because --container-tool and --container-commands commonly both
# contain docker.
remove_session_containers() {
  local runtime candidate home id seen
  local runtimes=()
  for candidate in "$CONTAINER_TOOL" $TEST_CONTAINER_RUNTIMES "$FORWARD_AUTH_CONTAINER_COMMAND"; do
    [[ -z "$candidate" || "$candidate" == "disable" ]] && continue
    seen=""
    for runtime in "${runtimes[@]}"; do
      [[ "$runtime" == "$candidate" ]] && seen=1
    done
    [[ -z "$seen" ]] && runtimes+=("$candidate")
  done

  for runtime in "${runtimes[@]}"; do
    command -v "$runtime" >/dev/null 2>&1 || continue

    while IFS= read -r id; do
      [[ -n "$id" ]] && "$runtime" rm -f "$id" >/dev/null 2>&1 || true
    done < <("$runtime" ps -aq \
      --filter "label=dev.openrun.test.session=$TEST_SESSION_ID" 2>/dev/null || true)

    for home in "${TEST_SERVER_HOMES[@]}"; do
      while IFS= read -r id; do
        [[ -n "$id" ]] && "$runtime" rm -f "$id" >/dev/null 2>&1 || true
      done < <("$runtime" ps -aq \
        --filter "label=dev.openrun.server.home=$home" 2>/dev/null || true)
    done
  done
}

cleanup() {
  [[ -n "$CLEANUP_DONE" ]] && return 0
  CLEANUP_DONE=1
  set +e

  # Stop only server processes started by this invocation. Stopping servers
  # before containers prevents health/status loops from racing cleanup.
  if [[ -n "$SERVER_PID" ]]; then
    kill -9 "$SERVER_PID" >/dev/null 2>&1 || true
    SERVER_PID=""
  fi
  if [[ -n "$DR_SERVER_PID" ]]; then
    kill -9 "$DR_SERVER_PID" >/dev/null 2>&1 || true
    DR_SERVER_PID=""
  fi

  remove_session_containers

  force_rm metadata app_src config1.json config2.json config_k8s.toml sync_test_id.tmp sqlite_tmp verifyapp_tmp kube_plugins versionstest disk_usage/config_gen.lock flaskhttp/config_gen.lock testapp/openrun_gen.go.html
  force_rm config/ logs/ openrun.toml config_container.toml server.stdout flaskapp testauthapp pg_flaskapp todo_flaskapp todo_rbac.json streamlitdev stdev_started.txt plugin_ext storeex_app/config_gen.lock

  if [[ -n "$POSTGRES_TEST_CONTAINER_ID" ]]; then
    $CONTAINER_TOOL rm -f "$POSTGRES_TEST_CONTAINER_ID" >/dev/null 2>&1 || true
    POSTGRES_TEST_CONTAINER_ID=""
  fi

  if [[ -n "$MYSQL_TEST_CONTAINER_ID" ]]; then
    $CONTAINER_TOOL rm -f "$MYSQL_TEST_CONTAINER_ID" >/dev/null 2>&1 || true
    MYSQL_TEST_CONTAINER_ID=""
  fi

  if [[ -n "$REDIS_TEST_CONTAINER_ID" ]]; then
    $CONTAINER_TOOL rm -f "$REDIS_TEST_CONTAINER_ID" >/dev/null 2>&1 || true
    REDIS_TEST_CONTAINER_ID=""
  fi

  if [[ -n "$SEAWEEDFS_TEST_CONTAINER_ID" ]]; then
    $CONTAINER_TOOL rm -f "$SEAWEEDFS_TEST_CONTAINER_ID" >/dev/null 2>&1 || true
    SEAWEEDFS_TEST_CONTAINER_ID=""
  fi
  force_rm config_litestream.toml seaweed_s3.json sqlite_ls_tmp

  # Disaster recovery scenario leftovers
  [[ -n "$DR_HOME1" ]] && rm -rf "$DR_HOME1"
  [[ -n "$DR_HOME2" ]] && rm -rf "$DR_HOME2"
  if [[ -n "$DR_KUBE_NS1" || -n "$DR_KUBE_NS2" ]]; then
    kubectl delete namespace $DR_KUBE_NS1 ${DR_KUBE_NS1:+$DR_KUBE_NS1-apps} $DR_KUBE_NS2 ${DR_KUBE_NS2:+$DR_KUBE_NS2-apps} --ignore-not-found --wait=false >/dev/null 2>&1 || true
    DR_KUBE_NS1=""
    DR_KUBE_NS2=""
  fi
  force_rm config_dr.toml dr_config_backup.toml sqlite_dr_tmp config_dr_k8s.toml sqlite_drk_tmp

  if [[ -n "$FORWARD_AUTH_CONTAINER_ID" ]]; then
    $FORWARD_AUTH_CONTAINER_COMMAND rm -f "$FORWARD_AUTH_CONTAINER_ID" >/dev/null 2>&1 || true
    FORWARD_AUTH_CONTAINER_ID=""
  fi

  if [[ -d ../appspecs_bk ]]; then
    rm -rf ../internal/server/appspecs
    mv ../appspecs_bk ../internal/server/appspecs
  fi

  if [[ -n "$KUBE_TEST_NAMESPACE_CREATED" && -n "$KUBE_TEST_NAMESPACE" ]]; then
    kubectl delete namespace "$KUBE_TEST_NAMESPACE" "${KUBE_TEST_NAMESPACE}-apps" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  fi

  # force_rm can use a short-lived labeled helper container for root-owned
  # files, so finish with one last session sweep as well.
  remove_session_containers

  # Github Actions does not seem to allow kill, the last echo is to allow the exit code to be zero
  echo "Done with cleanup"
}

# ERR covers command failures; EXIT also runs cleanup for normal completion and
# for INT/TERM exits (for example a local Ctrl-C or CI timeout).
trap error_handler ERR
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

start_forward_auth_testcontainer() {
  local container_command="$1"
  local port="$2"
  local expected_forward_host="$3"
  local image_name="openrun-testauth"

  rm -rf testauthapp
  mkdir testauthapp
  cp flask.py testauthapp/app.py
  printf "flask\n" > testauthapp/requirements.txt

  $container_command build -q -t "$image_name" -f flask_Dockerfile testauthapp >/dev/null
  FORWARD_AUTH_CONTAINER_COMMAND="$container_command"
  FORWARD_AUTH_CONTAINER_ID=$($container_command run \
    --detach \
    --rm \
    --label "dev.openrun.test.session=$TEST_SESSION_ID" \
    --publish 127.0.0.1:$port:5000 \
    --env EXPECTED_FORWARD_HOST="$expected_forward_host" \
    "$image_name")

  for _ in {1..60}; do
    if curl -fsS "http://127.0.0.1:$port/" >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done

  $container_command logs "$FORWARD_AUTH_CONTAINER_ID" || true
  echo "Forward auth test container did not start"
  return 1
}

stop_forward_auth_testcontainer() {
  if [[ -n "$FORWARD_AUTH_CONTAINER_ID" ]]; then
    $FORWARD_AUTH_CONTAINER_COMMAND rm -f "$FORWARD_AUTH_CONTAINER_ID" >/dev/null 2>&1 || true
    FORWARD_AUTH_CONTAINER_ID=""
  fi
}

start_postgres_testcontainer() {
  if [[ -n "$POSTGRES_URL_ARG" ]]; then
    export TEST_POSTGRES_URL="$POSTGRES_URL_ARG"
    echo "Using externally supplied TEST_POSTGRES_URL=$TEST_POSTGRES_URL"
    return
  fi

  local publish_addr="${POSTGRES_TEST_CONTAINER_PUBLISH_ADDR:-127.0.0.1}"
  echo "Starting postgres test container with $CONTAINER_TOOL"
  POSTGRES_TEST_CONTAINER_ID=$($CONTAINER_TOOL run \
    --detach \
    --rm \
    --label "dev.openrun.test.session=$TEST_SESSION_ID" \
    --publish "${publish_addr}::5432" \
    --env POSTGRES_DB=openrun_cli \
    --env POSTGRES_USER=postgres \
    --env POSTGRES_PASSWORD=postgres \
    postgres:17-alpine)

  local port=""
  for _ in {1..75}; do
    port=$($CONTAINER_TOOL inspect \
      --format '{{with index .NetworkSettings.Ports "5432/tcp"}}{{(index . 0).HostPort}}{{end}}' \
      "$POSTGRES_TEST_CONTAINER_ID" 2>/dev/null || true)
    if [[ -n "$port" ]]; then
      break
    fi
    sleep 0.2
  done

  if [[ -z "$port" ]]; then
    echo "Postgres test container port was not published"
    return 1
  fi

  local ready=""
  for _ in {1..300}; do
    # Check over TCP (-h 127.0.0.1), not the default unix socket: the postgres
    # image's init phase runs a temporary server that only listens on the
    # socket, so a socket-based pg_isready passes before the final server is
    # accepting connections on the published port.
    if $CONTAINER_TOOL exec "$POSTGRES_TEST_CONTAINER_ID" pg_isready -h 127.0.0.1 -U postgres -d openrun_cli >/dev/null 2>&1; then
      ready="true"
      break
    fi
    sleep 0.2
  done

  if [[ -z "$ready" ]]; then
    echo "Postgres test container did not become ready"
    $CONTAINER_TOOL logs "$POSTGRES_TEST_CONTAINER_ID" || true
    return 1
  fi

  export TEST_POSTGRES_URL="postgres://postgres:postgres@127.0.0.1:${port}/openrun_cli?sslmode=disable"
  echo "TEST_POSTGRES_URL=$TEST_POSTGRES_URL"
}

# start_seaweedfs_testcontainer starts a throwaway SeaweedFS instance (single
# container, S3 API on a published port) for the litestream replication
# suites, creates the test bucket and exports TEST_S3_*. With --s3-url the
# caller supplies an endpoint (plus TEST_S3_BUCKET/TEST_S3_ACCESS_KEY/
# TEST_S3_SECRET_KEY in the environment) instead.
start_seaweedfs_testcontainer() {
  if [[ -n "$TEST_S3_ENDPOINT" ]]; then
    return # already started (litestream phase and DR phase share the instance)
  fi
  if [[ -n "$S3_URL_ARG" ]]; then
    export TEST_S3_ENDPOINT="$S3_URL_ARG"
    if [[ -z "$TEST_S3_BUCKET" || -z "$TEST_S3_ACCESS_KEY" || -z "$TEST_S3_SECRET_KEY" ]]; then
      echo "--s3-url requires TEST_S3_BUCKET, TEST_S3_ACCESS_KEY and TEST_S3_SECRET_KEY to be set"
      return 1
    fi
    echo "Using externally supplied TEST_S3_ENDPOINT=$TEST_S3_ENDPOINT"
    return
  fi

  export TEST_S3_BUCKET="openrun-test"
  export TEST_S3_ACCESS_KEY="openrun_test_key"
  export TEST_S3_SECRET_KEY="openrun_test_secret"

  cat <<EOF > seaweed_s3.json
{
  "identities": [
    {
      "name": "openrun",
      "credentials": [
        {"accessKey": "$TEST_S3_ACCESS_KEY", "secretKey": "$TEST_S3_SECRET_KEY"}
      ],
      "actions": ["Admin", "Read", "Write", "List", "Tagging"]
    }
  ]
}
EOF

  echo "Starting SeaweedFS test container with $CONTAINER_TOOL"
  # Publish on all interfaces: the litestream sidecar containers reach the
  # endpoint through the host gateway alias (host.docker.internal). The
  # container name gives the kubernetes DR scenario a pod-resolvable OrbStack
  # domain. It is unique so concurrent test invocations cannot replace each
  # other's SeaweedFS container.
  SEAWEEDFS_TEST_CONTAINER_ID=$($CONTAINER_TOOL run \
    --detach \
    --rm \
    --name "$SEAWEEDFS_TEST_CONTAINER_NAME" \
    --label "dev.openrun.test.session=$TEST_SESSION_ID" \
    --publish "0.0.0.0::8333" \
    --volume "$PWD/seaweed_s3.json":/etc/seaweedfs/s3.json:ro \
    chrislusf/seaweedfs \
    server -s3 -s3.port=8333 -s3.config=/etc/seaweedfs/s3.json)

  local port=""
  for _ in {1..75}; do
    port=$($CONTAINER_TOOL inspect \
      --format '{{with index .NetworkSettings.Ports "8333/tcp"}}{{(index . 0).HostPort}}{{end}}' \
      "$SEAWEEDFS_TEST_CONTAINER_ID" 2>/dev/null || true)
    if [[ -n "$port" ]]; then
      break
    fi
    sleep 0.2
  done
  if [[ -z "$port" ]]; then
    echo "SeaweedFS test container port was not published"
    return 1
  fi

  local ready=""
  for _ in {1..300}; do
    # Any HTTP response (typically an S3 error document) means the S3 API is up
    if curl -s -o /dev/null "http://127.0.0.1:${port}/"; then
      ready="true"
      break
    fi
    sleep 0.2
  done
  if [[ -z "$ready" ]]; then
    echo "SeaweedFS test container did not become ready"
    $CONTAINER_TOOL logs "$SEAWEEDFS_TEST_CONTAINER_ID" || true
    return 1
  fi

  local created=""
  for _ in {1..60}; do
    if $CONTAINER_TOOL exec "$SEAWEEDFS_TEST_CONTAINER_ID" \
        sh -c "echo 's3.bucket.create -name $TEST_S3_BUCKET' | weed shell" 2>/dev/null | grep -qv "error"; then
      created="true"
      break
    fi
    sleep 0.5
  done
  if [[ -z "$created" ]]; then
    echo "SeaweedFS test bucket could not be created"
    $CONTAINER_TOOL logs "$SEAWEEDFS_TEST_CONTAINER_ID" || true
    return 1
  fi

  export TEST_S3_ENDPOINT="http://127.0.0.1:${port}"
  echo "TEST_S3_ENDPOINT=$TEST_S3_ENDPOINT bucket=$TEST_S3_BUCKET"
}

start_mysql_testcontainer() {
  if [[ -n "$MYSQL_URL_ARG" ]]; then
    export TEST_MYSQL_URL="$MYSQL_URL_ARG"
    echo "Using externally supplied TEST_MYSQL_URL=$TEST_MYSQL_URL"
    return
  fi

  local publish_addr="${MYSQL_TEST_CONTAINER_PUBLISH_ADDR:-127.0.0.1}"
  echo "Starting mysql test container with $CONTAINER_TOOL"
  MYSQL_TEST_CONTAINER_ID=$($CONTAINER_TOOL run \
    --detach \
    --rm \
    --label "dev.openrun.test.session=$TEST_SESSION_ID" \
    --publish "${publish_addr}::3306" \
    --env MYSQL_DATABASE=openrun_cli \
    --env MYSQL_ROOT_PASSWORD=mysql \
    mysql:8.4)
  export MYSQL_TEST_CONTAINER_ID
  # Tool for suites that exec into the container (e.g. out-of-band REVOKE in
  # test_mysql.yaml)
  export MYSQL_TEST_CONTAINER_COMMAND="$CONTAINER_TOOL"

  local port=""
  for _ in {1..75}; do
    port=$($CONTAINER_TOOL inspect \
      --format '{{with index .NetworkSettings.Ports "3306/tcp"}}{{(index . 0).HostPort}}{{end}}' \
      "$MYSQL_TEST_CONTAINER_ID" 2>/dev/null || true)
    if [[ -n "$port" ]]; then
      break
    fi
    sleep 0.2
  done

  if [[ -z "$port" ]]; then
    echo "MySQL test container port was not published"
    return 1
  fi

  local ready=""
  for _ in {1..300}; do
    if $CONTAINER_TOOL exec "$MYSQL_TEST_CONTAINER_ID" mysqladmin ping -h127.0.0.1 -uroot -pmysql --silent >/dev/null 2>&1; then
      ready="true"
      break
    fi
    sleep 0.2
  done

  if [[ -z "$ready" ]]; then
    echo "MySQL test container did not become ready"
    $CONTAINER_TOOL logs "$MYSQL_TEST_CONTAINER_ID" || true
    return 1
  fi

  export TEST_MYSQL_URL="mysql://root:mysql@127.0.0.1:${port}/openrun_cli?parseTime=true"
  echo "TEST_MYSQL_URL=$TEST_MYSQL_URL"
}

start_redis_testcontainer() {
  if [[ -n "$REDIS_URL_ARG" ]]; then
    export TEST_REDIS_URL="$REDIS_URL_ARG"
    echo "Using externally supplied TEST_REDIS_URL=$TEST_REDIS_URL"
    return
  fi

  # Set OPENRUN_TEST_REDIS_IMAGE=valkey/valkey:8-alpine to run against Valkey
  local image="${OPENRUN_TEST_REDIS_IMAGE:-redis:8-alpine}"
  echo "Starting redis test container $image with $CONTAINER_TOOL"
  REDIS_TEST_CONTAINER_ID=$($CONTAINER_TOOL run \
    --detach \
    --rm \
    --label "dev.openrun.test.session=$TEST_SESSION_ID" \
    --publish "127.0.0.1::6379" \
    "$image")
  export REDIS_TEST_CONTAINER_ID
  # Tool for suites that exec into the container (e.g. out-of-band ACL DELUSER
  # in test_redis.yaml)
  export REDIS_TEST_CONTAINER_COMMAND="$CONTAINER_TOOL"

  local port=""
  for _ in {1..75}; do
    port=$($CONTAINER_TOOL inspect \
      --format '{{with index .NetworkSettings.Ports "6379/tcp"}}{{(index . 0).HostPort}}{{end}}' \
      "$REDIS_TEST_CONTAINER_ID" 2>/dev/null || true)
    if [[ -n "$port" ]]; then
      break
    fi
    sleep 0.2
  done

  if [[ -z "$port" ]]; then
    echo "Redis test container port was not published"
    return 1
  fi

  local ready=""
  for _ in {1..300}; do
    if $CONTAINER_TOOL exec "$REDIS_TEST_CONTAINER_ID" \
        sh -c "redis-cli ping 2>/dev/null || valkey-cli ping" 2>/dev/null | grep -q PONG; then
      ready="true"
      break
    fi
    sleep 0.2
  done

  if [[ -z "$ready" ]]; then
    echo "Redis test container did not become ready"
    $CONTAINER_TOOL logs "$REDIS_TEST_CONTAINER_ID" || true
    return 1
  fi

  export TEST_REDIS_URL="redis://127.0.0.1:${port}"
  echo "TEST_REDIS_URL=$TEST_REDIS_URL"
}

# Test basic functionality
if is_selected test_basics.yaml; then
  rm -f run/openrun.sock
  # Use password hash for "abcd"
  cat <<EOF > config_basic_test.toml
[security]
admin_password_bcrypt = "\$2a\$10\$Hk5/XcvwrN.JRFrjdG0vjuGZxa5JaILdir1qflIj5i9DUPUyvIK7C"
app_default_auth_type = "system"
auth_required = true

[http]
port = $BASIC_HTTP_PORT
[https]
port = $BASIC_HTTPS_PORT

[system]
enable_compression = true

[client]
default_format = "table"
EOF

  wait_port_free "$SERVER_HTTP_PORT" && wait_port_free "$SERVER_HTTPS_PORT"
  CL_CONFIG_FILE=config_basic_test.toml GOCOVERDIR=$GOCOVERDIR ../openrun server start &
  SERVER_PID=$!
  wait_for_http "$BASIC_HTTP_PORT"

  cat <<EOF > config_basic_client_np.toml
server_uri = "http://localhost:$BASIC_HTTP_PORT"
EOF

  cat <<EOF > config_basic_client.toml
server_uri = "http://localhost:$BASIC_HTTP_PORT"
[client]
admin_password = "abcd"
EOF

  cat <<EOF > config_basic_client_https.toml
server_uri = "https://localhost:$BASIC_HTTPS_PORT"
[client]
admin_password = "abcd"
EOF

  cat <<EOF > config_basic_client_https_skip.toml
server_uri = "https://localhost:$BASIC_HTTPS_PORT"
[client]
admin_password = "abcd"
skip_cert_check = true
EOF

  commander test $VERBOSE test_basics.yaml
  MATCHED_TESTS+=(test_basics.yaml)
  # --wait exercises the wait-for-exit path (stop returns when shutdown
  # starts; --wait polls the server pid until the process is gone)
  CL_CONFIG_FILE=config_basic_test.toml GOCOVERDIR=$GOCOVERDIR/../client ../openrun server stop --wait
  SERVER_PID=""
  rm -rf metadata run/openrun.sock config_basic_*.toml
fi

if [[ ${#TESTS[@]} -eq 0 ]]; then
  cat <<EOF > config_np.toml
[http]
port = $SERVER_HTTP_PORT
[https]
port = $SERVER_HTTPS_PORT
EOF

  # Test server prints a password when started without config
  wait_port_free "$SERVER_HTTP_PORT" && wait_port_free "$SERVER_HTTPS_PORT"
  CL_CONFIG_FILE=config_np.toml GOCOVERDIR=$GOCOVERDIR ../openrun server start > server.stdout &
  SERVER_PID=$!
  wait_for_http "$SERVER_HTTP_PORT"
  grep "Admin password" server.stdout
  CL_CONFIG_FILE=config_np.toml GOCOVERDIR=$GOCOVERDIR/../client ../openrun server stop
  SERVER_PID=""
  rm -f run/openrun.sock config_np.toml
fi

# Test files that run against the main server (commander/*.yaml plus these
# top-level suites). Computed as an array so contains_any can tell whether
# any requested test needs the main server at all.
MAIN_PHASE_FILES=(test_service.yaml test_bindings.yaml test_app_update_bindings.yaml test_postgres.yaml test_mysql.yaml test_redis.yaml test_oauth.yaml test_github_auth.yaml)
for f in commander/*.yaml; do
  MAIN_PHASE_FILES+=("$(basename "$f")")
done

POSTGRES_FILES="test_service.yaml test_bindings.yaml test_app_update_bindings.yaml test_postgres.yaml test_postgres_container.yaml test_todo_flow.yaml"
MYSQL_FILES="test_mysql.yaml"
REDIS_FILES="test_redis.yaml"
CONTAINER_FILES="test_containers.yaml test_postgres_container.yaml test_todo_flow.yaml"
LITESTREAM_FILES="test_sqlite_litestream.yaml test_replication_status.yaml test_metadata_litestream.yaml test_metadata_litestream_verify.yaml"

if [[ -n "$ENABLE_POSTGRES" ]] && contains_any "$POSTGRES_FILES"; then
  if contains_any "test_postgres_container.yaml test_todo_flow.yaml"; then
    # Containerized apps connect to the test Postgres through POSTGRES_URL.
    # Publish on all host interfaces so Docker/Podman host aliases can reach the
    # mapped port from inside the app container.
    export POSTGRES_TEST_CONTAINER_PUBLISH_ADDR="${POSTGRES_TEST_CONTAINER_PUBLISH_ADDR:-0.0.0.0}"
  fi
  start_postgres_testcontainer
fi
if [[ -n "$ENABLE_MYSQL" ]] && contains_any "$MYSQL_FILES"; then
  start_mysql_testcontainer
fi
if [[ -n "$ENABLE_REDIS" ]] && contains_any "$REDIS_FILES"; then
  start_redis_testcontainer
fi

if contains_any "${MAIN_PHASE_FILES[*]}"; then
  # Run all other automated tests, use password hash for "qwerty"
  export CL_CONFIG_FILE=openrun.toml
  cat <<EOF > $CL_CONFIG_FILE
[security]
admin_password_bcrypt = "\$2a\$10\$PMaPsOVMBfKuDG04RsqJbeKIOJjlYi1Ie1KQbPCZRQx38bqYfernm"
callback_url = "https://localhost:$MAIN_HTTPS_PORT"
# The rbac suite's test app (tests/rbac_app, none auth) drives openrun_admin
# plugin calls as the anonymous user; allow that in the test env, like the
# console testenv does. The env_app/file_app/perms suites also use the exec
# system plugin
unsafe_allow_system_plugins_anon = true

[http]
port = $MAIN_HTTP_PORT

[permissions]
# Clear the default disallow of exec.in: the env_app/file_app/perms suites
# exercise exec plugin calls
disallow = []
EOF

  if contains_any "test_github_auth.yaml" && [[ -n "$CL_INFOCLACE_SSH" ]]; then
    # CL_INFOCLACE_SSH env is set, test authenticated git access with ssh key
    # infoopenrun user has read only access to openrun repo, which is anyway public
    echo "$CL_INFOCLACE_SSH" > ./infoopenrun_ssh
    chmod 600 ./infoopenrun_ssh

    cat <<EOF >> $CL_CONFIG_FILE
    [git_auth.infoopenrun]
    key_file_path = "./infoopenrun_ssh"

    [git_auth.testpat]
    user_id = "akopenrun"
    password="$TEST_PAT"
EOF
  fi

  if contains_any "test_oauth.yaml" && [[ -n "$CL_GITHUB_SECRET" ]]; then
    # CL_GITHUB_SECRET env is set, test github oauth login redirect

    cat <<EOF >> $CL_CONFIG_FILE

[auth.github_test]
key = "02507afb0ad9056fab09"
secret = "$CL_GITHUB_SECRET"

EOF
  fi

  cat <<EOF >> $CL_CONFIG_FILE
  # Static builtin auth user for test_builtin_auth.yaml, password is "abcd"
  [builtin_auth.statictester]
  password = "\$2a\$10\$Hk5/XcvwrN.JRFrjdG0vjuGZxa5JaILdir1qflIj5i9DUPUyvIK7C"
  groups = ["static-group"]

[https]
port = $MAIN_HTTPS_PORT
disable_client_certs = false

[secret.env]
keys_printf = "%s%s_%s"

[client_auth.cert_test1]
ca_cert_file="certs/testcerts1/ca.crt"

[client_auth.cert_test2]
ca_cert_file="certs/testcerts2/ca.crt"

[system]
enable_compression = true
# The commander suites intentionally reuse a small set of public git repos
# across many independent CLI requests. Keep immutable checkouts for this
# server lifetime so those cases test source handling instead of repeatedly
# downloading identical repository history.
git_checkout_cache_entries = 16
git_remote_check_interval_secs = 600

[client]
default_format = "table"

# Out-of-process Starlark plugin provider (store.ex), exercised by
# commander/test_plugin_ext.yaml. The binary is built below before the
# server starts.
[plugin_providers.dev_providers.store]
path = "./plugin_ext/openrun-plugin-store"

[plugin."store.ex"]
db_connection = "sqlite:./plugin_ext/openrun_storeex.db"
EOF

  # Build the store plugin provider used by commander/test_plugin_ext.yaml;
  # the server registers it at startup from plugin_providers.dev_providers
  rm -rf ./plugin_ext && mkdir -p ./plugin_ext
  go build -o ./plugin_ext/openrun-plugin-store ../internal/app/store/storeprovider

  export TESTENV=abc
  export c1c2_c3=xyz
  wait_port_free "$SERVER_HTTP_PORT" && wait_port_free "$SERVER_HTTPS_PORT"
  GOCOVERDIR=$GOCOVERDIR ../openrun server start &
  SERVER_PID=$!
  wait_for_http "$MAIN_HTTP_PORT"
  wait_for_socket

  if [[ ${#TESTS[@]} -eq 0 ]]; then
      commander test $VERBOSE --dir ./commander/
      if [[ -n "$TEST_POSTGRES_URL" ]]; then
          commander test $VERBOSE test_service.yaml
          commander test $VERBOSE test_bindings.yaml
          commander test $VERBOSE test_app_update_bindings.yaml
          commander test $VERBOSE test_postgres.yaml
      else
          echo "Skipping postgres service and binding tests; TEST_POSTGRES_URL is not set"
      fi
      if [[ -n "$TEST_MYSQL_URL" ]]; then
          commander test $VERBOSE test_mysql.yaml
      else
          echo "Skipping mysql service and binding tests; TEST_MYSQL_URL is not set"
      fi
      if [[ -n "$TEST_REDIS_URL" ]]; then
          commander test $VERBOSE test_redis.yaml
      else
          echo "Skipping redis service and binding tests; TEST_REDIS_URL is not set"
      fi
  else
      for name in "${TESTS[@]}"; do
        if [[ -f "commander/$name" ]]; then
            commander test $VERBOSE "commander/$name"
            MATCHED_TESTS+=("$name")
        elif [[ "$name" = "test_service.yaml" || "$name" = "test_bindings.yaml" || "$name" = "test_app_update_bindings.yaml" || "$name" = "test_postgres.yaml" ]]; then
            if [[ -n "$TEST_POSTGRES_URL" ]]; then
                commander test $VERBOSE "./$name"
            else
                echo "Skipping $name; TEST_POSTGRES_URL is not set"
            fi
            MATCHED_TESTS+=("$name")
        elif [[ "$name" = "test_mysql.yaml" ]]; then
            if [[ -n "$TEST_MYSQL_URL" ]]; then
                commander test $VERBOSE "./$name"
            else
                echo "Skipping $name; TEST_MYSQL_URL is not set"
            fi
            MATCHED_TESTS+=("$name")
        elif [[ "$name" = "test_redis.yaml" ]]; then
            if [[ -n "$TEST_REDIS_URL" ]]; then
                commander test $VERBOSE "./$name"
            else
                echo "Skipping $name; TEST_REDIS_URL is not set"
            fi
            MATCHED_TESTS+=("$name")
        fi
      done
  fi

  if contains_any "test_github_auth.yaml" && [[ -n "$CL_INFOCLACE_SSH" ]]; then
    # test git ssh key access
    commander test $VERBOSE test_github_auth.yaml
    MATCHED_TESTS+=(test_github_auth.yaml)
    rm ./infoopenrun_ssh
  fi

  if contains_any "test_oauth.yaml" && [[ -n "$CL_GITHUB_SECRET" ]]; then
    # test git oauth access are tested
    commander test $VERBOSE test_oauth.yaml
    MATCHED_TESTS+=(test_oauth.yaml)
  fi

  GOCOVERDIR=$GOCOVERDIR/../client ../openrun server stop
  SERVER_PID=""
fi

# Test containerized apps
ORIG_CONTAINER_COMMANDS="$CONTAINER_COMMANDS"
if [[ "$ORIG_CONTAINER_COMMANDS" = "disable" ]]; then
  ORIG_CONTAINER_COMMANDS=""
fi
if ! contains_any "$CONTAINER_FILES"; then
  CONTAINER_COMMANDS=""
elif [[ "$CONTAINER_COMMANDS" = "disable" ]]; then
  CONTAINER_COMMANDS=""
fi

export PYTHON_VERSION=3.14
for cmd in ${CONTAINER_COMMANDS}; do
    export OPENRUN_CONTAINER_COMMAND="$cmd"
    http_port=$SERVER_HTTP_PORT
    https_port=$SERVER_HTTPS_PORT
    forward_auth_port=$FORWARD_AUTH_PORT

    wait_port_free "$forward_auth_port"
    start_forward_auth_testcontainer "$cmd" "$forward_auth_port" "localhost:$http_port"

    cat <<EOF > config_container.toml
[http]
port = $http_port
[https]
port = $https_port
[system]
container_command="$cmd"

[app_config]
container.health_attempts_after_startup = 10
container.health_timeout_secs = 2

[forward.testauth]
auth_url = "http://127.0.0.1:$forward_auth_port/forward"
copy_response_headers = []

[security]
admin_password_bcrypt = "\$2a\$10\$Hk5/XcvwrN.JRFrjdG0vjuGZxa5JaILdir1qflIj5i9DUPUyvIK7C"
allowed_mounts = ["/tmp"]
allowed_container_args = { network = "regex:.*" }

[[permissions.allow]]
plugin = "proxy.in"
method = "config"
arguments = ["<CONTAINER_URL>"]

[[permissions.allow]]
plugin = "container.in"
method = "config"
arguments = ["regex:.*"]
secrets = [["regex:.*"]]

[secret.env]
EOF
    rm -rf metadata run/openrun.sock
    wait_port_free "$http_port" && wait_port_free "$https_port"
    CL_CONFIG_FILE=config_container.toml GOCOVERDIR=$GOCOVERDIR ../openrun server start &
    SERVER_PID=$!
    wait_for_http $http_port
    wait_for_socket

    export HTTP_PORT=$http_port
    # The CLI commands in the container yamls run with CL_CONFIG_FILE=openrun.toml
    # (set in the yaml config env) and connect over the unix socket. A full run's
    # main test block has already written openrun.toml; create an empty one for
    # selective runs (e.g. `run_cli_tests.sh test_containers.yaml`) that skip it
    [[ -f openrun.toml ]] || : > openrun.toml
    echo "********Testing containerized apps with $cmd*********"
    if is_selected test_containers.yaml; then
        commander test $VERBOSE test_containers.yaml
        MATCHED_TESTS+=(test_containers.yaml)
    fi
    if is_selected test_postgres_container.yaml; then
        if [[ -n "$TEST_POSTGRES_URL" ]]; then
            commander test $VERBOSE test_postgres_container.yaml
        else
            echo "Skipping test_postgres_container.yaml; TEST_POSTGRES_URL is not set"
        fi
        MATCHED_TESTS+=(test_postgres_container.yaml)
    fi
    if is_selected test_todo_flow.yaml; then
        if [[ -n "$TEST_POSTGRES_URL" ]]; then
            commander test $VERBOSE test_todo_flow.yaml
        else
            echo "Skipping test_todo_flow.yaml; TEST_POSTGRES_URL is not set"
        fi
        MATCHED_TESTS+=(test_todo_flow.yaml)
    fi
    CL_CONFIG_FILE=config_container.toml GOCOVERDIR=$GOCOVERDIR/../client ../openrun server stop
    SERVER_PID=""
    stop_forward_auth_testcontainer
done

# Litestream replication suites: need an S3 endpoint (--seaweedfs) and a
# container command for the app + sidecar containers
LITESTREAM_CONTAINER_CMD="${ORIG_CONTAINER_COMMANDS%% *}"
if [[ -n "$ENABLE_SEAWEEDFS" && -n "$LITESTREAM_CONTAINER_CMD" ]] && contains_any "$LITESTREAM_FILES"; then
  start_seaweedfs_testcontainer

  ls_http_port=$SERVER_HTTP_PORT
  ls_https_port=$SERVER_HTTPS_PORT
  cat <<EOF > config_litestream.toml
[http]
port = $ls_http_port
[https]
port = $ls_https_port

[security]
admin_password_bcrypt = "\$2a\$10\$PMaPsOVMBfKuDG04RsqJbeKIOJjlYi1Ie1KQbPCZRQx38bqYfernm"

[system]
container_command="$LITESTREAM_CONTAINER_CMD"

[app_config]
container.health_attempts_after_startup = 10
container.health_timeout_secs = 2

# Short sync interval so the suites see replication advance quickly
[litestream.s3test]
endpoint = "$TEST_S3_ENDPOINT"
bucket = "$TEST_S3_BUCKET"
region = "us-east-1"
path_prefix = "openrun-int"
access_key_id = "$TEST_S3_ACCESS_KEY"
secret_access_key = "$TEST_S3_SECRET_KEY"
force_path_style = true
sync_interval = "200ms"
snapshot_interval = "10m"

# File replica type: valid for metadata, rejected for sqlite services
[litestream.localdisk]
type = "file"
path = "/tmp/openrun-litestream-test"

[metadata]
litestream_config = "s3test"
EOF

  start_litestream_test_server() {
    rm -f run/openrun.sock
    wait_port_free "$ls_http_port" && wait_port_free "$ls_https_port"
    CL_CONFIG_FILE=config_litestream.toml GOCOVERDIR=$GOCOVERDIR ../openrun server start &
    SERVER_PID=$!
    wait_for_http "$ls_http_port"
    wait_for_socket
  }

  rm -rf metadata
  start_litestream_test_server
  export HTTP_PORT=$ls_http_port
  export OPENRUN_CONTAINER_COMMAND="$LITESTREAM_CONTAINER_CMD"
  [[ -f openrun.toml ]] || : > openrun.toml
  echo "********Testing litestream replication with $LITESTREAM_CONTAINER_CMD*********"

  if is_selected test_sqlite_litestream.yaml; then
    commander test $VERBOSE test_sqlite_litestream.yaml
    MATCHED_TESTS+=(test_sqlite_litestream.yaml)
  fi
  if is_selected test_replication_status.yaml; then
    commander test $VERBOSE test_replication_status.yaml
    MATCHED_TESTS+=(test_replication_status.yaml)
  fi
  if is_selected test_metadata_litestream.yaml; then
    commander test $VERBOSE test_metadata_litestream.yaml
    MATCHED_TESTS+=(test_metadata_litestream.yaml)

    # Metadata disaster recovery: stop the server (final litestream sync),
    # wipe the metadata directory, restart and verify the state was restored
    # from the S3 replica. `server stop` returns when shutdown STARTS; the
    # final sync that carries the just-created entries runs as the process
    # exits, so wait for the exit or the wipe below races the sync and the
    # restore comes back stale
    CL_CONFIG_FILE=config_litestream.toml GOCOVERDIR=$GOCOVERDIR/../client ../openrun server stop
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""
    rm -rf metadata
    start_litestream_test_server
    commander test $VERBOSE test_metadata_litestream_verify.yaml
    MATCHED_TESTS+=(test_metadata_litestream_verify.yaml)
  fi

  CL_CONFIG_FILE=config_litestream.toml GOCOVERDIR=$GOCOVERDIR/../client ../openrun server stop
  # Wait for the process exit before deleting the metadata directory, so the
  # shutdown's final litestream sync does not race the deletion
  wait "$SERVER_PID" 2>/dev/null || true
  SERVER_PID=""
  rm -rf metadata run/openrun.sock
fi

# Disaster recovery scenario: full node loss and rebuild from the S3 replica.
# A server in a throwaway OPENRUN_HOME replicates its metadata and a sqlite
# app to SeaweedFS; the server is then hard-killed and everything except the
# config file is destroyed (home directory with the metadata databases, app
# container, litestream sidecar, data volume). A second server in a fresh
# OPENRUN_HOME with the backed-up config must restore the metadata (app list,
# audit history) and the app's sqlite data from the replica alone.
#
# Disabled by default (it is slow and hard-kills a server): runs when
# explicitly requested, e.g. ./tests/run_cli_tests.sh --seaweedfs test_dr_sqlite.yaml,
# or in a full run with --dr
if [[ -n "$ENABLE_SEAWEEDFS" && -n "$LITESTREAM_CONTAINER_CMD" ]] && dr_selected test_dr_sqlite.yaml; then
  start_seaweedfs_testcontainer

  # Unique replica prefix per run so a rerun never restores a previous run's data
  DR_PATH_PREFIX="dr-$(date +%s)-$$"
  dr_http_port=$SERVER_HTTP_PORT
  dr_https_port=$SERVER_HTTPS_PORT
  cat <<EOF > config_dr.toml
[http]
port = $dr_http_port
[https]
port = $dr_https_port

[security]
admin_password_bcrypt = "\$2a\$10\$PMaPsOVMBfKuDG04RsqJbeKIOJjlYi1Ie1KQbPCZRQx38bqYfernm"

[system]
container_command="$LITESTREAM_CONTAINER_CMD"

[app_config]
container.health_attempts_after_startup = 10
container.health_timeout_secs = 2

[litestream.drtest]
endpoint = "$TEST_S3_ENDPOINT"
bucket = "$TEST_S3_BUCKET"
region = "us-east-1"
path_prefix = "$DR_PATH_PREFIX"
access_key_id = "$TEST_S3_ACCESS_KEY"
secret_access_key = "$TEST_S3_SECRET_KEY"
force_path_style = true
sync_interval = "200ms"
snapshot_interval = "10m"

[metadata]
litestream_config = "drtest"
EOF

  echo "********Testing disaster recovery with $LITESTREAM_CONTAINER_CMD*********"
  export HTTP_PORT=$dr_http_port
  export OPENRUN_CONTAINER_COMMAND="$LITESTREAM_CONTAINER_CMD"

  # Phase 1: fresh home, litestream-enabled server, app with sqlite data
  DR_HOME1=$(mktemp -d)
  start_dr_server "$DR_HOME1" config_dr.toml
  DR_HOME="$DR_HOME1" commander test $VERBOSE test_dr_sqlite.yaml
  MATCHED_TESTS+=(test_dr_sqlite.yaml)

  # Backup the config, then destroy the node: hard-kill the server (no final
  # sync; the suite waited for replication to catch up), remove the app/stage
  # containers, the sidecars, their data volumes and the whole home directory
  # including the metadata database files
  cp config_dr.toml dr_config_backup.toml
  kill -9 "$DR_SERVER_PID" 2>/dev/null || true
  DR_SERVER_PID=""
  sleep 1
  DR_CONTAINERS=$($LITESTREAM_CONTAINER_CMD ps -aq --filter label=dev.openrun.app.path=/dr_app)
  DR_VOLUMES=""
  if [[ -n "$DR_CONTAINERS" ]]; then
    DR_VOLUMES=$($LITESTREAM_CONTAINER_CMD inspect --format '{{range .Mounts}}{{.Name}} {{end}}' $DR_CONTAINERS 2>/dev/null | tr ' ' '\n' | grep '^clv-' | sort -u || true)
    $LITESTREAM_CONTAINER_CMD rm -f $DR_CONTAINERS >/dev/null
  fi
  if [[ -n "$DR_VOLUMES" ]]; then
    $LITESTREAM_CONTAINER_CMD volume rm -f $DR_VOLUMES >/dev/null
  fi
  rm -rf "$DR_HOME1"
  DR_HOME1=""

  # Phase 2: fresh home, the backed-up config, everything restored from S3
  DR_HOME2=$(mktemp -d)
  cp dr_config_backup.toml config_dr.toml
  start_dr_server "$DR_HOME2" config_dr.toml
  DR_HOME="$DR_HOME2" commander test $VERBOSE test_dr_sqlite_verify.yaml
  MATCHED_TESTS+=(test_dr_sqlite_verify.yaml)

  OPENRUN_HOME="$DR_HOME2" CL_CONFIG_FILE=config_dr.toml GOCOVERDIR=$GOCOVERDIR/../client ../openrun server stop
  DR_SERVER_PID=""
  rm -rf "$DR_HOME2"
  DR_HOME2=""

  # Remove the containers and volumes the rebuilt server created (containers
  # normally outlive the server; this scenario's server homes are gone)
  DR_CONTAINERS=$($LITESTREAM_CONTAINER_CMD ps -aq --filter label=dev.openrun.app.path=/dr_app)
  if [[ -n "$DR_CONTAINERS" ]]; then
    DR_VOLUMES=$($LITESTREAM_CONTAINER_CMD inspect --format '{{range .Mounts}}{{.Name}} {{end}}' $DR_CONTAINERS 2>/dev/null | tr ' ' '\n' | grep '^clv-' | sort -u || true)
    $LITESTREAM_CONTAINER_CMD rm -f $DR_CONTAINERS >/dev/null
    if [[ -n "$DR_VOLUMES" ]]; then
      $LITESTREAM_CONTAINER_CMD volume rm -f $DR_VOLUMES >/dev/null
    fi
  fi
  rm -f config_dr.toml dr_config_backup.toml
  rm -rf sqlite_dr_tmp
fi

# Kubernetes disaster recovery scenario: like the docker scenario above, but
# the app runs on the kubernetes container manager. The original deployment
# lands in one namespace; after the node loss (hard-killed server, deleted
# namespace with its PVC, wiped OPENRUN_HOME) the rebuilt server deploys into
# a SECOND namespace, restoring the metadata from S3 and the app data into a
# fresh PVC via the restore init containers.
#
# Disabled by default: needs --seaweedfs and --kube-registry, and runs when
# explicitly requested, e.g.
#   ./tests/run_cli_tests.sh --seaweedfs --kube-registry registry.orb.local:5000 test_dr_kubernetes.yaml
# or in a full run with --dr. This block must stay ahead of the
# test_kubernetes.yaml block below: the DR scenario runs before the full
# kubernetes suite.
if [[ -n "$ENABLE_SEAWEEDFS" && -n "$KUBE_REGISTRY_URL" ]] && dr_selected test_dr_kubernetes.yaml; then
  start_seaweedfs_testcontainer

  # Pods cannot reach the host's 127.0.0.1 SeaweedFS endpoint. Default the
  # pod-visible endpoint (litestream container_endpoint) per setup: for an
  # OrbStack registry the SeaweedFS container's own orb.local domain; else
  # the SeaweedFS published port on the registry host (which the cluster
  # already reaches for image pulls). Override with --kube-s3-endpoint.
  KUBE_S3_ENDPOINT="$KUBE_S3_ENDPOINT_ARG"
  if [[ -z "$KUBE_S3_ENDPOINT" ]]; then
    if [[ -n "$S3_URL_ARG" ]]; then
      echo "--s3-url with the kubernetes DR scenario requires --kube-s3-endpoint (pod-visible endpoint)"
      exit 1
    fi
    if [[ "$KUBE_REGISTRY_URL" == *".orb.local"* ]]; then
      KUBE_S3_ENDPOINT="http://${SEAWEEDFS_TEST_CONTAINER_NAME}.orb.local:8333"
    else
      registry_host="${KUBE_REGISTRY_URL#http://}"
      registry_host="${registry_host#https://}"
      registry_host="${registry_host%%/*}"
      registry_host="${registry_host%%:*}"
      if [[ "$registry_host" == *.svc.cluster.local ]]; then
        # The registry is a cluster-internal service (e.g. the k3s CI runner):
        # its DNS name resolves to a ClusterIP that only serves the registry
        # port. SeaweedFS publishes on all host interfaces, so pods reach it
        # through the node IP instead.
        registry_host=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
      fi
      KUBE_S3_ENDPOINT="http://${registry_host}:${TEST_S3_ENDPOINT##*:}"
    fi
  fi
  echo "Kubernetes pod-visible S3 endpoint: $KUBE_S3_ENDPOINT"

  DR_KUBE_NS1="openrun-dr1-$$"
  DR_KUBE_NS2="openrun-dr2-$$"
  # The kubernetes manager deploys apps into "<namespace>-apps"
  for ns in "$DR_KUBE_NS1" "$DR_KUBE_NS1-apps" "$DR_KUBE_NS2" "$DR_KUBE_NS2-apps"; do
    kubectl create namespace "$ns" --dry-run=client -o yaml | kubectl apply -f -
  done

  # Unique replica prefix per run so a rerun never restores a previous run's data
  DRK_PATH_PREFIX="drk-$(date +%s)-$$"
  write_dr_k8s_config() { # $1 = kubernetes namespace
    cat <<EOF > config_dr_k8s.toml
[http]
port = $SERVER_HTTP_PORT
[https]
port = $SERVER_HTTPS_PORT

[security]
admin_password_bcrypt = "\$2a\$10\$PMaPsOVMBfKuDG04RsqJbeKIOJjlYi1Ie1KQbPCZRQx38bqYfernm"

[secret.env]

[system]
container_command="kubernetes"

[kubernetes]
namespace = "$1"
use_node_port = true

[registry]
url="$KUBE_REGISTRY_URL"
insecure = true

[app_config]
container.health_attempts_after_startup = 20
container.health_timeout_secs = 1
container.deploy_probe_period_secs = 1
container.deploy_health_attempts = 30
container.deploy_progress_deadline_secs = 20
container.status_health_attempts = 3
container.idle_shutdown_secs = 900
container.status_check_interval_secs = 60

[litestream.drtest]
endpoint = "$TEST_S3_ENDPOINT"
container_endpoint = "$KUBE_S3_ENDPOINT"
bucket = "$TEST_S3_BUCKET"
region = "us-east-1"
path_prefix = "$DRK_PATH_PREFIX"
access_key_id = "$TEST_S3_ACCESS_KEY"
secret_access_key = "$TEST_S3_SECRET_KEY"
force_path_style = true
sync_interval = "200ms"
snapshot_interval = "10m"

[metadata]
litestream_config = "drtest"
EOF
  }

  echo "********Testing kubernetes disaster recovery (namespaces $DR_KUBE_NS1 -> $DR_KUBE_NS2)*********"
  export HTTP_PORT=$SERVER_HTTP_PORT
  export DR_KUBE_NS1 DR_KUBE_NS2
  [[ -f openrun.toml ]] || : > openrun.toml

  # Phase 1: fresh home, kubernetes server deploying into namespace 1
  write_dr_k8s_config "$DR_KUBE_NS1"
  DR_HOME1=$(mktemp -d)
  start_dr_server "$DR_HOME1" config_dr_k8s.toml
  DR_HOME="$DR_HOME1" commander test $VERBOSE test_dr_kubernetes.yaml
  MATCHED_TESTS+=(test_dr_kubernetes.yaml)

  # Backup the config, then destroy the node: hard-kill the server, delete
  # the whole first namespace (deployment, pods with the sidecar, PVC with
  # the app data) and the home directory with the metadata databases
  cp config_dr_k8s.toml dr_config_backup.toml
  kill -9 "$DR_SERVER_PID" 2>/dev/null || true
  DR_SERVER_PID=""
  sleep 1
  kubectl delete namespace "$DR_KUBE_NS1" "$DR_KUBE_NS1-apps" --wait=false >/dev/null
  rm -rf "$DR_HOME1"
  DR_HOME1=""

  # Phase 2: fresh home, the backed-up config pointed at namespace 2
  DR_HOME2=$(mktemp -d)
  sed "s/namespace = \"$DR_KUBE_NS1\"/namespace = \"$DR_KUBE_NS2\"/" dr_config_backup.toml > config_dr_k8s.toml
  start_dr_server "$DR_HOME2" config_dr_k8s.toml
  DR_HOME="$DR_HOME2" commander test $VERBOSE test_dr_kubernetes_verify.yaml
  MATCHED_TESTS+=(test_dr_kubernetes_verify.yaml)

  OPENRUN_HOME="$DR_HOME2" CL_CONFIG_FILE=config_dr_k8s.toml GOCOVERDIR=$GOCOVERDIR/../client ../openrun server stop
  DR_SERVER_PID=""
  rm -rf "$DR_HOME2"
  DR_HOME2=""
  kubectl delete namespace "$DR_KUBE_NS2" "$DR_KUBE_NS2-apps" --wait=false >/dev/null
  DR_KUBE_NS1=""
  DR_KUBE_NS2=""
  rm -f config_dr_k8s.toml dr_config_backup.toml
  rm -rf sqlite_drk_tmp
fi

if [[ -n "$KUBE_REGISTRY_URL" ]] && contains_any "test_kubernetes.yaml"; then
  # test kubernetes container manager
  if [[ -z "$KUBE_TEST_NAMESPACE" ]]; then
    KUBE_TEST_NAMESPACE="openrun-cli-test-$$"
    KUBE_TEST_NAMESPACE_CREATED=true
  fi
  kubectl create namespace "$KUBE_TEST_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
  kubectl create namespace "${KUBE_TEST_NAMESPACE}-apps" --dry-run=client -o yaml | kubectl apply -f -

  # Match the Helm chart's db secrets setup: keep the encryption key outside
  # the metadata database in a namespace-scoped Kubernetes Secret, and resolve
  # it through [secret.db]. The fixed value is test-only key material.
  KUBE_DB_KEY_SECRET="openrun-db-secrets-key"
  KUBE_DB_KEY_MATERIAL="kube1:MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE="
  kubectl create secret generic "$KUBE_DB_KEY_SECRET" \
    --namespace "$KUBE_TEST_NAMESPACE" \
    --from-literal="key=$KUBE_DB_KEY_MATERIAL" \
    --dry-run=client -o yaml | kubectl apply -f -

  # OCI binding provider distribution test setup: the fixture provider is
  # built once for the host (registered with the local server through
  # bindings.preinstalled_dir, as the chart's shared volume would be) and once
  # for the cluster platform, packaged as a FROM scratch image and pushed to
  # the test registry (pulled by the init container in test_kubernetes.yaml).
  KUBE_BINDINGS_DIR="$(pwd)/kube_bindings"
  rm -rf "$KUBE_BINDINGS_DIR"
  mkdir -p "$KUBE_BINDINGS_DIR/preinstalled"
  (cd ../internal/bindings/testdata/fixtureprovider && \
    GOWORK=off CGO_ENABLED=0 go build -o "$KUBE_BINDINGS_DIR/preinstalled/openrun-binding-fixture" .)
  KUBE_NODE_ARCH=$(kubectl get nodes -o jsonpath='{.items[0].status.nodeInfo.architecture}')
  (cd ../internal/bindings/testdata/fixtureprovider && \
    GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH="$KUBE_NODE_ARCH" go build -o "$KUBE_BINDINGS_DIR/openrun-binding-fixture-linux" .)
  cat <<EOF > "$KUBE_BINDINGS_DIR/Dockerfile"
FROM scratch
COPY openrun-binding-fixture-linux /openrun-binding-fixture
ENTRYPOINT ["/openrun-binding-fixture"]
EOF
  export KUBE_BINDING_IMAGE="$KUBE_REGISTRY_URL/openrun-binding-fixture:cli-test"
  $CONTAINER_TOOL build --platform "linux/$KUBE_NODE_ARCH" -q -t "$KUBE_BINDING_IMAGE" "$KUBE_BINDINGS_DIR"
  # Push through go-containerregistry instead of the Docker CLI. Docker has no
  # per-push insecure-registry option, so using `docker push` here requires
  # modifying the runner machine's daemon configuration for an HTTP registry.
  KUBE_BINDING_ARCHIVE="$KUBE_BINDINGS_DIR/openrun-binding-fixture.tar"
  $CONTAINER_TOOL save -o "$KUBE_BINDING_ARCHIVE" "$KUBE_BINDING_IMAGE"
  go run ./registry_push --insecure --tar "$KUBE_BINDING_ARCHIVE" "$KUBE_BINDING_IMAGE"

  # OCI plugin provider distribution test setup, mirroring the bindings setup
  # above: the store plugin provider is built once for the host (registered
  # through plugin_providers.preinstalled_dir) and once for the cluster
  # platform, packaged as a FROM scratch image and pushed to the test registry.
  KUBE_PLUGINS_DIR="$(pwd)/kube_plugins"
  rm -rf "$KUBE_PLUGINS_DIR"
  mkdir -p "$KUBE_PLUGINS_DIR/preinstalled"
  go build -o "$KUBE_PLUGINS_DIR/preinstalled/openrun-plugin-store" ../internal/app/store/storeprovider
  (cd .. && CGO_ENABLED=0 GOOS=linux GOARCH="$KUBE_NODE_ARCH" go build -o "$KUBE_PLUGINS_DIR/openrun-plugin-store-linux" ./internal/app/store/storeprovider)
  cat <<EOF > "$KUBE_PLUGINS_DIR/Dockerfile"
FROM scratch
COPY openrun-plugin-store-linux /openrun-plugin-store
ENTRYPOINT ["/openrun-plugin-store"]
EOF
  export KUBE_PLUGIN_IMAGE="$KUBE_REGISTRY_URL/openrun-plugin-store:cli-test"
  $CONTAINER_TOOL build --platform "linux/$KUBE_NODE_ARCH" -q -t "$KUBE_PLUGIN_IMAGE" "$KUBE_PLUGINS_DIR"
  KUBE_PLUGIN_ARCHIVE="$KUBE_PLUGINS_DIR/openrun-plugin-store.tar"
  $CONTAINER_TOOL save -o "$KUBE_PLUGIN_ARCHIVE" "$KUBE_PLUGIN_IMAGE"
  go run ./registry_push --insecure --tar "$KUBE_PLUGIN_ARCHIVE" "$KUBE_PLUGIN_IMAGE"
  export KUBE_TEST_NAMESPACE

  cat <<EOF > config_k8s.toml
[http]
port = $SERVER_HTTP_PORT
[https]
port = $SERVER_HTTPS_PORT
[secret.env]
[secret.kubernetes]
[secret.db]
key = '{{secret_from "kubernetes" "$KUBE_DB_KEY_SECRET" "key"}}'
[system]
container_command="kubernetes"
[kubernetes]
namespace = "$KUBE_TEST_NAMESPACE"
use_node_port = true
[registry]
url="$KUBE_REGISTRY_URL"
insecure = true
[bindings]
preinstalled_dir = "$KUBE_BINDINGS_DIR/preinstalled"
disable_install = true
[plugin_providers]
preinstalled_dir = "$KUBE_PLUGINS_DIR/preinstalled"
disable_install = true
[plugin."store.ex"]
db_connection = "sqlite:$KUBE_PLUGINS_DIR/openrun_storeex_k8s.db"
[app_config]
container.health_attempts_after_startup = 20
container.health_timeout_secs = 1
container.deploy_probe_period_secs = 1
container.deploy_health_attempts = 30
container.deploy_progress_deadline_secs = 20
container.status_health_attempts = 3
container.idle_shutdown_secs = 900
container.status_check_interval_secs = 60
EOF

    rm -rf metadata run/openrun.sock
    # The CLI commands in test_kubernetes.yaml run with CL_CONFIG_FILE=openrun.toml
    # (commander replaces the environment with the yaml env map). In a full run the
    # main test block has already written openrun.toml; create an empty one for
    # standalone runs (`run_cli_tests.sh --kube-registry ... test_kubernetes.yaml`)
    # so the CLI does not fail parsing a missing config file.
    [[ -f openrun.toml ]] || : > openrun.toml
    wait_port_free "$SERVER_HTTP_PORT" && wait_port_free "$SERVER_HTTPS_PORT"
    CL_CONFIG_FILE=config_k8s.toml GOCOVERDIR=$GOCOVERDIR ../openrun server start &
    SERVER_PID=$!
    wait_for_http "$SERVER_HTTP_PORT"
    wait_for_socket

    export HTTP_PORT=$SERVER_HTTP_PORT
    echo "********Testing containerized apps with kubernetes *********"
    commander test $VERBOSE test_kubernetes.yaml
    MATCHED_TESTS+=(test_kubernetes.yaml)
    CL_CONFIG_FILE=config_k8s.toml GOCOVERDIR=$GOCOVERDIR/../client ../openrun server stop
    SERVER_PID=""
fi

cleanup

if [[ ${#TESTS[@]} -gt 0 ]]; then
  for name in "${TESTS[@]}"; do
    found=""
    for m in "${MATCHED_TESTS[@]}"; do
      [[ "$m" == "$name" ]] && found=1
    done
    if [[ -z "$found" ]]; then
      echo "Warning: requested test '$name' did not match any known suite (or its prerequisite, e.g. --postgres/--kube-registry, was not enabled)" >&2
    fi
  done
fi

echo "Test run completed: ${TESTS[*]:-all}"
