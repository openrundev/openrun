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

Kubernetes (only runs when --kube-registry is set):
  --kube-registry URL      Container registry the Kubernetes suite pushes to
  --kube-namespace NAME     Namespace to use (default: openrun-cli-test-$$)

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
CONTAINER_COMMANDS="docker"
CONTAINER_TOOL="docker"
ENABLE_POSTGRES=""
ENABLE_MYSQL=""
POSTGRES_URL_ARG=""
MYSQL_URL_ARG=""
KUBE_REGISTRY_URL=""
KUBE_TEST_NAMESPACE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --home) HOME_DIR="$2"; shift 2 ;;
    --coverdir) COVERDIR="$2"; shift 2 ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    --verbose) VERBOSE="--verbose"; shift ;;
    --container-commands) CONTAINER_COMMANDS="$2"; shift 2 ;;
    --container-tool) CONTAINER_TOOL="$2"; shift 2 ;;
    --postgres) ENABLE_POSTGRES=1; shift ;;
    --postgres-url) ENABLE_POSTGRES=1; POSTGRES_URL_ARG="$2"; shift 2 ;;
    --mysql) ENABLE_MYSQL=1; shift ;;
    --mysql-url) ENABLE_MYSQL=1; MYSQL_URL_ARG="$2"; shift 2 ;;
    --kube-registry) KUBE_REGISTRY_URL="$2"; shift 2 ;;
    --kube-namespace) KUBE_TEST_NAMESPACE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    -*) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
    *) break ;;
  esac
done
TESTS=("$@")
MATCHED_TESTS=()

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
      go build -cover ./cmd/openrun
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
unset CL_CONFIG_FILE
unset SSH_AUTH_SOCK

trap "error_handler" ERR

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
# block is regenerated (not just retried) on any hit.
pick_port_base() {
  local base attempt
  for attempt in {1..30}; do
    base=$(( 20000 + (RANDOM % 380) * 100 ))
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

cleanup() {
  rm -rf metadata app_src config1.json config2.json config_k8s.toml sync_test_id.tmp sqlite_tmp verifyapp_tmp disk_usage/config_gen.lock flaskhttp/config_gen.lock testapp/openrun_gen.go.html
  rm -rf config/ logs/ openrun.toml config_container.toml server.stdout flaskapp testauthapp pg_flaskapp todo_flaskapp todo_rbac.json streamlitdev stdev_started.txt

  if [[ -n "$POSTGRES_TEST_CONTAINER_ID" ]]; then
    $CONTAINER_TOOL rm -f "$POSTGRES_TEST_CONTAINER_ID" >/dev/null 2>&1 || true
    POSTGRES_TEST_CONTAINER_ID=""
  fi

  if [[ -n "$MYSQL_TEST_CONTAINER_ID" ]]; then
    $CONTAINER_TOOL rm -f "$MYSQL_TEST_CONTAINER_ID" >/dev/null 2>&1 || true
    MYSQL_TEST_CONTAINER_ID=""
  fi

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

  set +e
  server_pids=$(ps -ax | grep "openrun server start" | grep -v grep | awk '{print $1}')
  if [[ -n "$server_pids" ]]; then
    kill -9 $server_pids
  fi

  # Github Actions does not seem to allow kill, the last echo is to allow the exit code to be zero
  echo "Done with cleanup"
}

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
  CL_CONFIG_FILE=config_basic_test.toml GOCOVERDIR=$GOCOVERDIR/../client ../openrun server stop
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
  wait_for_http "$SERVER_HTTP_PORT"
  grep "Admin password" server.stdout
  CL_CONFIG_FILE=config_np.toml GOCOVERDIR=$GOCOVERDIR/../client ../openrun server stop
  rm -f run/openrun.sock config_np.toml
fi

# Test files that run against the main server (commander/*.yaml plus these
# top-level suites). Computed as an array so contains_any can tell whether
# any requested test needs the main server at all.
MAIN_PHASE_FILES=(test_service.yaml test_bindings.yaml test_app_update_bindings.yaml test_postgres.yaml test_mysql.yaml test_oauth.yaml test_github_auth.yaml)
for f in commander/*.yaml; do
  MAIN_PHASE_FILES+=("$(basename "$f")")
done

POSTGRES_FILES="test_service.yaml test_bindings.yaml test_app_update_bindings.yaml test_postgres.yaml test_postgres_container.yaml test_todo_flow.yaml"
MYSQL_FILES="test_mysql.yaml"
CONTAINER_FILES="test_containers.yaml test_postgres_container.yaml test_todo_flow.yaml"

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

[client]
default_format = "table"
EOF

  export TESTENV=abc
  export c1c2_c3=xyz
  wait_port_free "$SERVER_HTTP_PORT" && wait_port_free "$SERVER_HTTPS_PORT"
  GOCOVERDIR=$GOCOVERDIR ../openrun server start &
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
fi

# Test containerized apps
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
    stop_forward_auth_testcontainer
done

if [[ -n "$KUBE_REGISTRY_URL" ]] && contains_any "test_kubernetes.yaml"; then
  # test kubernetes container manager
  if [[ -z "$KUBE_TEST_NAMESPACE" ]]; then
    KUBE_TEST_NAMESPACE="openrun-cli-test-$$"
    KUBE_TEST_NAMESPACE_CREATED=true
  fi
  kubectl create namespace "$KUBE_TEST_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
  kubectl create namespace "${KUBE_TEST_NAMESPACE}-apps" --dry-run=client -o yaml | kubectl apply -f -

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
  $CONTAINER_TOOL push "$KUBE_BINDING_IMAGE"
  export KUBE_TEST_NAMESPACE

  cat <<EOF > config_k8s.toml
[http]
port = $SERVER_HTTP_PORT
[https]
port = $SERVER_HTTPS_PORT
[secret.env]
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
    wait_for_http "$SERVER_HTTP_PORT"
    wait_for_socket

    export HTTP_PORT=$SERVER_HTTP_PORT
    echo "********Testing containerized apps with kubernetes *********"
    commander test $VERBOSE test_kubernetes.yaml
    MATCHED_TESTS+=(test_kubernetes.yaml)
    CL_CONFIG_FILE=config_k8s.toml GOCOVERDIR=$GOCOVERDIR/../client ../openrun server stop
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
