FROM node:22-bookworm

ENV ANDROID_SDK_ROOT=/opt/android-sdk
ENV ANDROID_HOME=/opt/android-sdk
ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
ENV PATH=$PATH:/opt/android-sdk/cmdline-tools/latest/bin:/opt/android-sdk/platform-tools:/opt/android-sdk/build-tools/35.0.0
ENV DEFAULT_LICENSE_SERVER=https://android-license-gateway-phone.pages.dev
ENV PORT=7860

RUN apt-get update \
  && apt-get install -y --no-install-recommends openjdk-17-jdk unzip wget ca-certificates \
  && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/android-sdk/cmdline-tools \
  && wget -q https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip -O /tmp/cmdline-tools.zip \
  && unzip -q /tmp/cmdline-tools.zip -d /opt/android-sdk/cmdline-tools \
  && mv /opt/android-sdk/cmdline-tools/cmdline-tools /opt/android-sdk/cmdline-tools/latest \
  && rm /tmp/cmdline-tools.zip \
  && yes | sdkmanager --licenses >/dev/null \
  && sdkmanager "platform-tools" "platforms;android-35" "build-tools;35.0.0"

WORKDIR /app
COPY package.json ./
COPY server.js ./

RUN mkdir -p tools work out

EXPOSE 7860
CMD ["node", "server.js"]
