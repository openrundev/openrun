# Running OpenRun CLI tests

This folder has the tests for the OpenRun CLI. The tests use the [Commander](https://github.com/commander-cli/commander) CLI test framework.

Install Commander by running

`go install github.com/commander-cli/commander/v2/cmd/commander@latest`

and then run the whole suite from the repo root with

`./tests/run_cli_tests.sh`

By default this builds `./openrun` from the current checkout and runs every test file. Ports are picked at random for each run, so you can run this from multiple checkouts (e.g. git worktrees) at the same time without them colliding on TCP ports.

Run `./tests/run_cli_tests.sh --help` for the full list of flags. A few common ones:

- Run a single suite: `./tests/run_cli_tests.sh test_reload.yaml` (setup for unrelated suites, e.g. starting container test servers, is skipped)
- Run several suites: `./tests/run_cli_tests.sh test_reload.yaml test_certs.yaml`
- Skip the `go build` step when iterating on a yaml file: `--skip-build`
- Pick which container tools to test app containers with (default is `docker podman`; on a machine/CI runner without container support, use `--container-commands disable`):
  `./tests/run_cli_tests.sh --container-commands docker`
- Run the Postgres/MySQL dependent suites: `--postgres` / `--mysql` starts a throwaway test container; `--postgres-url`/`--mysql-url` points at an already-running instance instead
- Run the litestream replication suites (sqlite bindings + metadata backup): `--seaweedfs` starts a throwaway SeaweedFS container as the S3 endpoint; `--s3-url` points at an already-running S3-compatible endpoint instead (set `TEST_S3_BUCKET`, `TEST_S3_ACCESS_KEY` and `TEST_S3_SECRET_KEY`)
- Run the disaster recovery scenario (disabled by default; hard-kills a throwaway server, destroys its home/containers/volumes and rebuilds everything from the S3 replica): `./tests/run_cli_tests.sh --seaweedfs test_dr_sqlite.yaml`
- Run the kubernetes disaster recovery scenario (disabled by default; original deployment in one namespace, rebuild into a second namespace): `./tests/run_cli_tests.sh --seaweedfs --kube-registry registry.orb.local:5000 test_dr_kubernetes.yaml`. Pods must be able to reach the S3 endpoint: with an OrbStack registry the SeaweedFS container's orb.local domain is used automatically, otherwise the SeaweedFS port on the registry host; `--kube-s3-endpoint` overrides.
- Run the Kubernetes container-manager suite: `--kube-registry <registry-url>` (optionally `--kube-namespace <name>`)

From the repo root, `make int` / `make int_single <test-file.yaml>` / `make covint` wrap the script (see the Makefile for the `CONTAINER_COMMANDS`, `POSTGRES`, `MYSQL`, `KUBE_REGISTRY`, etc. make variables they forward). Note `make` needs GNU Make 4.0+; on macOS the default `make` is older, so call the script directly or use `gmake` (`brew install make`).

The CLI tests are run as part of the Github Actions [workflow](https://github.com/openrundev/openrun/blob/main/.github/workflows/test.yml).

Git auth secrets (`CL_INFOCLACE_SSH`, `CL_GITHUB_SECRET`, `TEST_PAT`) stay as environment variables rather than flags, so they don't show up in the process list; set them to enable `test_github_auth.yaml` / `test_oauth.yaml`.
