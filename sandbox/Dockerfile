FROM debian:bookworm-slim

RUN apt-get update && \
  apt-get install --no-install-recommends -y \
  ca-certificates \
  jq \
  curl \
  zsh \
  git \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

RUN adduser claude

# Create directories and set permissions
COPY .zshrc /home/claude/.zshrc
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && chown -R claude:claude /home/claude

# Create app directory and set ownership
WORKDIR /workspace
RUN chown -R claude:claude /workspace
# Declare the fixed workdir as a mount point
VOLUME ["/workspace"]

# Create /opt directory and set ownership for happy repo
RUN mkdir -p /opt && chown -R claude:claude /opt

# Switch to non-root user
USER claude

ENV NVM_DIR="/home/claude/.nvm"
RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash && \
  . ~/.nvm/nvm.sh && \
  nvm install 22 && \
  nvm use 22 && \
  nvm alias default 22

# Configure git with default username and email
RUN git config --global user.name "Claude" && \
  git config --global user.email "claude@example.com"

RUN \
  . ~/.nvm/nvm.sh && \
  npm install -g @anthropic-ai/claude-code@latest && \
  # Install yarn globally
  npm install -g yarn && \
  # Clone and build happy-cli
  git clone https://github.com/lava/happy-cli.git /opt/happy && \
  cd /opt/happy && \
  yarn install && \
  yarn build && \
  npm install -g .

ENTRYPOINT ["/entrypoint.sh"]
CMD ["happy"]
