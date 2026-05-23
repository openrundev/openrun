#set -x
set -eE

# Enabling verbose is useful for debugging but the commander command seems to
# return exit code of 0 when verbose is enabled, even if tests fails. So verbose
# is disabled by default.
#export CL_TEST_VERBOSE="--verbose"

cd $OPENRUN_HOME
export GOCOVERDIR=$GOCOVERDIR

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

cd tests
rm -rf metadata

export OPENRUN_HOME=.
unset CL_CONFIG_FILE
unset SSH_AUTH_SOCK

trap "error_handler" ERR

error_handler () {
    echo "Error occurred, running cleanup"
    cleanup
    echo "Test failed"
    exit 1
}

cleanup() {
  rm -rf metadata app_src config1.json config2.json config_k8s.toml sync_test_id.tmp disk_usage/config_gen.lock flaskhttp/config_gen.lock testapp/openrun_gen.go.html
  rm -rf config/ logs/ openrun.toml config_container.toml server.stdout flaskapp testauthapp pg_flaskapp

  if [[ -n "$POSTGRES_TEST_CONTAINER_ID" ]]; then
    $POSTGRES_TEST_CONTAINER_COMMAND rm -f "$POSTGRES_TEST_CONTAINER_ID" >/dev/null 2>&1 || true
    POSTGRES_TEST_CONTAINER_ID=""
  fi
  if [[ -n "$POSTGRES_TEST_CONTAINER_NETWORK" ]]; then
    $POSTGRES_TEST_CONTAINER_COMMAND network rm "$POSTGRES_TEST_CONTAINER_NETWORK" >/dev/null 2>&1 || true
    POSTGRES_TEST_CONTAINER_NETWORK=""
  fi

  if [[ -n "$FORWARD_AUTH_CONTAINER_ID" ]]; then
    $FORWARD_AUTH_CONTAINER_COMMAND rm -f "$FORWARD_AUTH_CONTAINER_ID" >/dev/null 2>&1 || true
    FORWARD_AUTH_CONTAINER_ID=""
  fi

  if [[ -d ../appspecs_bk ]]; then
    rm -rf ../internal/server/appspecs
    mv ../appspecs_bk ../internal/server/appspecs
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
  if [[ -z "$ENABLE_POSTGRES_TESTCONTAINER" ]]; then
    return
  fi

  POSTGRES_TEST_CONTAINER_COMMAND="${OPENRUN_TEST_CONTAINER_COMMAND:-docker}"
  local publish_addr="${POSTGRES_TEST_CONTAINER_PUBLISH_ADDR:-127.0.0.1}"
  local network_args=()
  if [[ -n "$POSTGRES_TEST_CONTAINER_NETWORK" ]]; then
    $POSTGRES_TEST_CONTAINER_COMMAND network rm "$POSTGRES_TEST_CONTAINER_NETWORK" >/dev/null 2>&1 || true
    $POSTGRES_TEST_CONTAINER_COMMAND network create "$POSTGRES_TEST_CONTAINER_NETWORK" >/dev/null
    network_args=(--network "$POSTGRES_TEST_CONTAINER_NETWORK" --network-alias openrun-postgres)
  fi
  echo "Starting postgres test container with $POSTGRES_TEST_CONTAINER_COMMAND"
  POSTGRES_TEST_CONTAINER_ID=$($POSTGRES_TEST_CONTAINER_COMMAND run \
    --detach \
    --rm \
    --publish "${publish_addr}::5432" \
    "${network_args[@]}" \
    --env POSTGRES_DB=openrun_cli \
    --env POSTGRES_USER=postgres \
    --env POSTGRES_PASSWORD=postgres \
    postgres:17-alpine)

  local port=""
  for _ in {1..75}; do
    port=$($POSTGRES_TEST_CONTAINER_COMMAND inspect \
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
    if $POSTGRES_TEST_CONTAINER_COMMAND exec "$POSTGRES_TEST_CONTAINER_ID" pg_isready -U postgres -d openrun_cli >/dev/null 2>&1; then
      ready="true"
      break
    fi
    sleep 0.2
  done

  if [[ -z "$ready" ]]; then
    echo "Postgres test container did not become ready"
    $POSTGRES_TEST_CONTAINER_COMMAND logs "$POSTGRES_TEST_CONTAINER_ID" || true
    return 1
  fi

  export TEST_POSTGRES_URL="postgres://postgres:postgres@127.0.0.1:${port}/openrun_cli?sslmode=disable"
  echo "TEST_POSTGRES_URL=$TEST_POSTGRES_URL"
}

# Test basic functionality
rm -f run/openrun.sock
# Use password hash for "abcd"
cat <<EOF > config_basic_test.toml
[security]
admin_password_bcrypt = "\$2a\$10\$Hk5/XcvwrN.JRFrjdG0vjuGZxa5JaILdir1qflIj5i9DUPUyvIK7C"
app_default_auth_type = "system"
auth_required = true

[http]
port = 9154
[https]
port = 9155

[system]
enable_compression = true

[client]
default_format = "table"
EOF

CL_CONFIG_FILE=config_basic_test.toml GOCOVERDIR=$GOCOVERDIR ../openrun server start &
sleep 2

cat <<EOF > config_basic_client_np.toml
server_uri = "http://localhost:9154"
EOF

cat <<EOF > config_basic_client.toml
server_uri = "http://localhost:9154"
[client]
admin_password = "abcd"
EOF

cat <<EOF > config_basic_client_https.toml
server_uri = "https://localhost:9155"
[client]
admin_password = "abcd"
EOF

cat <<EOF > config_basic_client_https_skip.toml
server_uri = "https://localhost:9155"
[client]
admin_password = "abcd"
skip_cert_check = true
EOF

if [[ -z $CL_SINGLE_TEST ]]; then
    commander test $CL_TEST_VERBOSE test_basics.yaml
fi
CL_CONFIG_FILE=config_basic_test.toml GOCOVERDIR=$GOCOVERDIR/../client ../openrun server stop
rm -rf metadata run/openrun.sock config_basic_*.toml

cat <<EOF > config_np.toml
[http]
port = 9156
[https]
port = 9157
EOF

# Test server prints a password when started without config
CL_CONFIG_FILE=config_np.toml GOCOVERDIR=$GOCOVERDIR ../openrun server start > server.stdout &
sleep 2
grep "Admin password" server.stdout
CL_CONFIG_FILE=config_np.toml GOCOVERDIR=$GOCOVERDIR/../client ../openrun server stop
rm -f run/openrun.sock config_np.toml

# Run all other automated tests, use password hash for "qwerty"
export CL_CONFIG_FILE=openrun.toml
cat <<EOF > $CL_CONFIG_FILE
[security]
admin_password_bcrypt = "\$2a\$10\$PMaPsOVMBfKuDG04RsqJbeKIOJjlYi1Ie1KQbPCZRQx38bqYfernm"
callback_url = "https://localhost:25223"
EOF

if [[ -n "$CL_INFOCLACE_SSH" ]]; then
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

if [[ -n "$CL_GITHUB_SECRET" ]]; then
  # CL_GITHUB_SECRET env is set, test github oauth login redirect

  cat <<EOF >> $CL_CONFIG_FILE

[auth.github_test]
key = "02507afb0ad9056fab09"
secret = "$CL_GITHUB_SECRET"

EOF
fi

cat <<EOF >> $CL_CONFIG_FILE
[https]
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
if [[ "$CL_CONTAINER_COMMANDS" != "disable" && ( -z "$CL_SINGLE_TEST" || "$CL_SINGLE_TEST" = "test_postgres_container.yaml" ) ]]; then
  # Containerized apps need to reach the test Postgres from inside their own
  # container. Put the app and Postgres containers on one user-defined network
  # so the app can connect to the postgres alias on port 5432.
  export POSTGRES_TEST_CONTAINER_PUBLISH_ADDR="${POSTGRES_TEST_CONTAINER_PUBLISH_ADDR:-0.0.0.0}"
  export POSTGRES_TEST_CONTAINER_NETWORK="${POSTGRES_TEST_CONTAINER_NETWORK:-openrun-postgres-test}"
fi
start_postgres_testcontainer
GOCOVERDIR=$GOCOVERDIR ../openrun server start &
sleep 2

if [[ -z $CL_SINGLE_TEST ]]; then
    commander test $CL_TEST_VERBOSE --dir ./commander/
    if [[ -n "$TEST_POSTGRES_URL" ]]; then
        commander test $CL_TEST_VERBOSE test_service.yaml
        commander test $CL_TEST_VERBOSE test_bindings.yaml
        commander test $CL_TEST_VERBOSE test_app_update_bindings.yaml
        commander test $CL_TEST_VERBOSE test_postgres.yaml
    else
        echo "Skipping postgres service and binding tests; TEST_POSTGRES_URL is not set"
    fi
elif [[ $CL_SINGLE_TEST != "disable" ]]; then
    if [[ $CL_SINGLE_TEST = "test_service.yaml" || $CL_SINGLE_TEST = "test_bindings.yaml" || $CL_SINGLE_TEST = "test_app_update_bindings.yaml" || $CL_SINGLE_TEST = "test_postgres.yaml" ]]; then
        if [[ -n "$TEST_POSTGRES_URL" ]]; then
            commander test $CL_TEST_VERBOSE ./$CL_SINGLE_TEST
        else
            echo "Skipping $CL_SINGLE_TEST; TEST_POSTGRES_URL is not set"
        fi
    elif [[ $CL_SINGLE_TEST = "test_containers.yaml" || $CL_SINGLE_TEST = "test_postgres_container.yaml" ]]; then
        echo "Deferring $CL_SINGLE_TEST to containerized app test phase"
    else
        commander test $CL_TEST_VERBOSE ./commander/$CL_SINGLE_TEST
    fi
fi

if [[ -n $CL_SINGLE_TEST && -z $CL_TEST_CONTAINER && "$CL_SINGLE_TEST" != "test_containers.yaml" && "$CL_SINGLE_TEST" != "test_postgres_container.yaml" ]]; then
    CL_CONTAINER_COMMANDS="disable"
fi

echo $?

if [[ -n "$CL_INFOCLACE_SSH" ]]; then
  # test git ssh key access
  commander test $CL_TEST_VERBOSE test_github_auth.yaml
  rm ./infoopenrun_ssh
fi

if [[ -n "$CL_GITHUB_SECRET" ]]; then
  # test git oauth access are tested 
  commander test $CL_TEST_VERBOSE test_oauth.yaml
fi

GOCOVERDIR=$GOCOVERDIR/../client ../openrun server stop


# Test containerized apps
if [[ $CL_CONTAINER_COMMANDS = "disable" ]]; then
  CL_CONTAINER_COMMANDS=""
elif [[ -z "$CL_CONTAINER_COMMANDS" ]]; then
  CL_CONTAINER_COMMANDS="docker podman"
fi

export PYTHON_VERSION=3.14
port_base=9000
for cmd in ${CL_CONTAINER_COMMANDS}; do
    export OPENRUN_CONTAINER_COMMAND="$cmd"
    http_port=`expr $port_base + 1`
    https_port=`expr $port_base + 2`
    forward_auth_port=`expr $port_base + 3`
    port_base=`expr $port_base + 3`

    start_forward_auth_testcontainer "$cmd" "$forward_auth_port" "localhost:$http_port"

    cat <<EOF > config_container.toml
[http]
port = $http_port
[https]
port = $https_port
[system]
container_command="$cmd"

[forward.testauth]
auth_url = "http://127.0.0.1:$forward_auth_port/forward"
copy_response_headers = []

[security]
admin_password_bcrypt = "\$2a\$10\$Hk5/XcvwrN.JRFrjdG0vjuGZxa5JaILdir1qflIj5i9DUPUyvIK7C"
allowed_mounts = ["/tmp"]
allowed_container_args = { network = "regex:.*", add-host = "regex:.*" }

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
    CL_CONFIG_FILE=config_container.toml GOCOVERDIR=$GOCOVERDIR ../openrun server start &
    sleep 2

    export HTTP_PORT=$http_port
    echo "********Testing containerized apps with $cmd*********"
    if [[ -z "$CL_SINGLE_TEST" || "$CL_SINGLE_TEST" = "test_containers.yaml" ]]; then
        commander test $CL_TEST_VERBOSE test_containers.yaml
    fi
    if [[ -z "$CL_SINGLE_TEST" || "$CL_SINGLE_TEST" = "test_postgres_container.yaml" ]]; then
        if [[ -n "$TEST_POSTGRES_URL" ]]; then
            if [[ -z "$POSTGRES_TEST_CONTAINER_COMMAND" || "$cmd" = "$POSTGRES_TEST_CONTAINER_COMMAND" ]]; then
                commander test $CL_TEST_VERBOSE test_postgres_container.yaml
            else
                echo "Skipping test_postgres_container.yaml for $cmd; postgres test container is running under $POSTGRES_TEST_CONTAINER_COMMAND"
            fi
        else
            echo "Skipping test_postgres_container.yaml; TEST_POSTGRES_URL is not set"
        fi
    fi
    CL_CONFIG_FILE=config_container.toml GOCOVERDIR=$GOCOVERDIR/../client ../openrun server stop
    stop_forward_auth_testcontainer
done

if [[ $KUBE_REGISTRY_URL != "" ]]; then
  # test kubernetes container manager
  cat <<EOF > config_k8s.toml
[http]
port = 9100
[https]
port = 9101
[secret.env]
[system]
container_command="kubernetes"
[kubernetes]
use_node_port = true
[registry]
url="$KUBE_REGISTRY_URL"
insecure = true
[appconfig]
container.health_attempts_after_startup = 40
EOF

    rm -rf metadata run/openrun.sock
    CL_CONFIG_FILE=config_k8s.toml GOCOVERDIR=$GOCOVERDIR ../openrun server start &
    sleep 2

    export HTTP_PORT=9100
    echo "********Testing containerized apps with kubernetes *********"
    commander test $CL_TEST_VERBOSE test_kubernetes.yaml
    CL_CONFIG_FILE=config_k8s.toml GOCOVERDIR=$GOCOVERDIR/../client ../openrun server stop
fi

cleanup
echo "Test $CL_SINGLE_TEST completed"
