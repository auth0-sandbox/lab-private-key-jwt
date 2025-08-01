# The devcontainer.json file defines a build so the Dockerfile is used to build a new image.
# The base image is from Microsoft at https://mcr.microsoft.com/en-us/artifact/mar/devcontainers/javascript-node/tags.
# The number is the toolchain version, which in this image is the Node version (22 is current LTS).
# The name "bookworm" refers to the Debian Bookworm release, which is the base OS for this image, adding the name
# fixes the Linux release used.

FROM mcr.microsoft.com/vscode/devcontainers/javascript-node:dev-24-bookworm

ENV DEBIAN_FRONTEND=noninteractive
RUN sudo apt update && sudo apt-get install -y --no-install-recommends mkcert

# # This installs the GitHub CLI (gh) for use in GitHub Codespaces.
RUN curl -L -o /tmp/gh-amd.deb https://github.com/cli/cli/releases/download/v2.53.0/gh_2.53.0_linux_amd64.deb
RUN curl -L -o /tmp/gh-arm.deb https://github.com/cli/cli/releases/download/v2.53.0/gh_2.53.0_linux_arm64.deb
RUN apt-get install -y ./$(uname -m | grep -q '^aarch64\|^arm' && echo /tmp/gh-arm.deb || echo /tmp/gh-amd.deb)

# [Optional] Uncomment if you want to install an additional version of node using nvm
# ARG EXTRA_NODE_VERSION=10
# RUN su node -c "source /usr/local/share/nvm/nvm.sh && nvm install ${EXTRA_NODE_VERSION}"

# [Optional] Uncomment if you want to install more global node modules
# RUN su node -c "npm install -g --slient npm parcel-bundler concurrently eslint prettier"