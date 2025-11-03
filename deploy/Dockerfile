# Copyright (c) ClaceIO, LLC
# SPDX-License-Identifier: Apache-2.0

FROM alpine:3.22.2
ARG TARGETARCH
ENV OPENRUN_HOME=/var/lib/openrun

# Create non-root user and directories
RUN addgroup -S openrun \
 && adduser -S -G openrun -h /home/openrun openrun \
 && mkdir -p  "${OPENRUN_HOME}" \
 && chown -R openrun:openrun "${OPENRUN_HOME}"

COPY linux/${TARGETARCH}/openrun /usr/bin/openrun

USER openrun
EXPOSE 25222
EXPOSE 25223

CMD ["/usr/bin/openrun", "server", "start"]

