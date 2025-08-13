# Running OpenRun CLI tests

This folder has the tests for the OpenRun CLI. The tests use the [Commander](https://github.com/commander-cli/commander) CLI test framework.

To run the tests, ensure that OPENRUN_HOME env variable points to the OpenRun code base location. Install Commander by running

`go install github.com/commander-cli/commander/v2/cmd/commander@latest`

and then run

`$OPENRUN_HOME/tests/run_cli_tests.sh`

The CLI tests are run as part of the Github Actions [workflow](https://github.com/openrundev/openrun/blob/e1c2d85b5a8139fd16f7ccaf227d8521187f8974/.github/workflows/test.yml#L44)

Container tests are run locally with both Docker and Podman by default (when `CL_CONTAINER_COMMANDS` is unset). To change to run with just docker for example, set
`export CL_CONTAINER_COMMANDS=docker`

To disable container tests, set
`export CL_CONTAINER_COMMANDS=disable`

Container tests are not run by default on GitHub actions since starting containers is not supported on the default workers.
