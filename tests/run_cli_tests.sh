#set -x
set -e

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
  rm -rf metadata app_src
  rm -rf logs/ openrun.toml config_container.toml server.stdout flaskapp

  if [[ -d ../appspecs_bk ]]; then
    rm -rf ../internal/server/appspecs
    mv ../appspecs_bk ../internal/server/appspecs
  fi 

  set +e
  ps -ax | grep "openrun server start" | grep -v grep | cut -c1-6 | xargs kill -9

  # Github Actions does not seem to allow kill, the last echo is to allow the exit code to be zero
  echo "Done with cleanup"
}

# Test basic functionality
rm -f run/openrun.sock
# Use password hash for "abcd"
cat <<EOF > config_basic_test.toml
[security]
admin_password_bcrypt = "\$2a\$10\$Hk5/XcvwrN.JRFrjdG0vjuGZxa5JaILdir1qflIj5i9DUPUyvIK7C"
app_default_auth_type = "system"

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
GOCOVERDIR=$GOCOVERDIR ../openrun server start &
sleep 2

if [[ -z $CL_SINGLE_TEST ]]; then
    commander test $CL_TEST_VERBOSE  --dir ./commander/
else
    commander test $CL_TEST_VERBOSE ./commander/$CL_SINGLE_TEST
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

export PYTHON_VERSION=3.12.4-slim
port_base=9000
for cmd in ${CL_CONTAINER_COMMANDS}; do
    http_port=`expr $port_base + 1`
    https_port=`expr $port_base + 2`
    port_base=`expr $port_base + 2`

    cat <<EOF > config_container.toml
[http]
port = $http_port
[https]
port = $https_port
[system]
container_command="$cmd"
[secret.env]
EOF
    rm -rf metadata run/openrun.sock
    CL_CONFIG_FILE=config_container.toml GOCOVERDIR=$GOCOVERDIR ../openrun server start &
    sleep 2

    export HTTP_PORT=$http_port
    echo "********Testing containerized apps with $cmd*********"
    commander test $CL_TEST_VERBOSE test_containers.yaml
    CL_CONFIG_FILE=config_container.toml GOCOVERDIR=$GOCOVERDIR/../client ../openrun server stop
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
