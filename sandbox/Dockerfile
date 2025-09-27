FROM debian:bookworm-slim as happy-sandbox

RUN apt-get update && \
  apt-get install --no-install-recommends -y \
  ca-certificates \
  jq \
  curl \
  zsh \
  git \
  gpg \
  wget \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

# Install GitHub CLI
RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | gpg --dearmor -o /usr/share/keyrings/githubcli-archive-keyring.gpg && \
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | tee /etc/apt/sources.list.d/github-cli.list > /dev/null && \
  apt-get update && \
  apt-get install --no-install-recommends -y gh && \
  apt-get clean && \
  rm -rf /var/lib/apt/lists/*

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
  # Install codex CLI
  npm install -g @openai/codex && \
  # Clone and build happy-cli
  git clone https://github.com/lava/happy-cli.git /opt/happy && \
  cd /opt/happy && \
  yarn install && \
  yarn build && \
  npm install -g .

ENTRYPOINT ["/entrypoint.sh"]
CMD ["happy"]

# Android SDK stage - extends the base happy-sandbox
FROM happy-sandbox as happy-sandbox-android

# Switch back to root to install additional packages
USER root

RUN apt-get update && \
  apt-get install --no-install-recommends -y \
  wget \
  unzip \
  openjdk-17-jdk \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

# Install Android SDK
ENV ANDROID_SDK_ROOT=/opt/android/sdk
ENV PATH=$PATH:$ANDROID_SDK_ROOT/cmdline-tools/latest/bin:$ANDROID_SDK_ROOT/platform-tools

RUN mkdir -p $ANDROID_SDK_ROOT && \
    cd /opt && \
    wget -q https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip && \
    unzip -q commandlinetools-linux-11076708_latest.zip && \
    mkdir -p $ANDROID_SDK_ROOT/cmdline-tools && \
    mv cmdline-tools $ANDROID_SDK_ROOT/cmdline-tools/latest && \
    rm commandlinetools-linux-11076708_latest.zip && \
    yes | $ANDROID_SDK_ROOT/cmdline-tools/latest/bin/sdkmanager --licenses && \
    $ANDROID_SDK_ROOT/cmdline-tools/latest/bin/sdkmanager \
      "platform-tools" \
      "platforms;android-34" \
      "build-tools;34.0.0" && \
    chown -R claude:claude $ANDROID_SDK_ROOT

# Switch back to non-root user
USER claude

# Create CLAUDE.local.md with Android SDK instructions
RUN echo '# Android SDK Information\n\
\n\
The Android SDK is installed in this container at `/opt/android/sdk`.\n\
\n\
## Environment Variables\n\
- `ANDROID_SDK_ROOT`: /opt/android/sdk\n\
- `PATH`: Includes Android SDK cmdline-tools and platform-tools\n\
\n\
## Installed Components\n\
- Android SDK Command-line Tools (latest)\n\
- Android SDK Platform-tools\n\
- Android SDK Platform 34 (Android 14)\n\
- Android SDK Build-tools 34.0.0\n\
\n\
## Using the Android SDK\n\
\n\
### SDK Manager\n\
Use `sdkmanager` to install additional SDK components:\n\
```bash\n\
sdkmanager --list  # List available packages\n\
sdkmanager "platforms;android-33"  # Install Android 13 platform\n\
```\n\
\n\
### ADB (Android Debug Bridge)\n\
ADB is available at `adb` and can be used to interact with Android devices:\n\
```bash\n\
adb devices  # List connected devices\n\
adb shell    # Open shell on device\n\
```\n\
\n\
### Building Android Apps\n\
To build Android apps, you may need to set up Gradle. The Android SDK provides:\n\
- Platform tools for building APKs\n\
- Build tools for compilation\n\
- Platform libraries for target SDK versions\n\
\n\
### Creating AVDs (Android Virtual Devices)\n\
```bash\n\
avdmanager create avd -n test -k "system-images;android-34;google_apis;x86_64"\n\
```\n\
\n\
Note: Running emulators requires additional setup and may not work in all container environments.' > /home/claude/CLAUDE.local.md

ENTRYPOINT ["/entrypoint.sh"]
CMD ["happy"]
