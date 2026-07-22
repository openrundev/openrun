# Copyright (c) ClaceIO, LLC
# SPDX-License-Identifier: Apache-2.0

FROM alpine:3.22.2
ARG TARGETARCH
ENV OPENRUN_HOME=/var/lib/openrun
# In-place restarts are disabled in containers: the server is pid 1, so the
# old process exiting after a listener handoff would terminate the container
# and kill the new process. Restart the container instead
ENV OPENRUN_IN_CONTAINER=1

# Create non-root user and directories
RUN addgroup -S openrun \
 && adduser -S -G openrun -h /home/openrun openrun \
 && mkdir -p  "${OPENRUN_HOME}" \
 && chown -R openrun:openrun "${OPENRUN_HOME}"

COPY --chmod=0555 linux/${TARGETARCH}/openrun /usr/bin/openrun

USER openrun
EXPOSE 25222 25223
ENTRYPOINT ["/usr/bin/openrun", "server", "start"]

