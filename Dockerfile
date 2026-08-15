FROM node:22-bookworm

ENV ANDROID_SDK_ROOT=/opt/android-sdk
ENV ANDROID_HOME=/opt/android-sdk
ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
ENV PATH=$PATH:/opt/android-sdk/cmdline-tools/latest/bin:/opt/android-sdk/platform-tools:/opt/android-sdk/build-tools/35.0.0
ENV DEFAULT_LICENSE_SERVER=https://android-license-gateway-phone.pages.dev
ENV PORT=7860
ARG STABLE_V20_PROTECTED_APK_URL=https://github.com/3012636630/android-card-license-server/releases/download/stable-v20-assets-v1/protected.apk
ARG STABLE_V20_PROTECTED_APK_SHA256=ac321ade0724ac9f5413dc57533aadfc503587ef3c5cc3319ed9761047266279

RUN apt-get update \
  && apt-get install -y --no-install-recommends openjdk-17-jdk unzip wget ca-certificates python3 python3-pip \
  && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/android-sdk/cmdline-tools \
  && wget -q https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip -O /tmp/cmdline-tools.zip \
  && unzip -q /tmp/cmdline-tools.zip -d /opt/android-sdk/cmdline-tools \
  && mv /opt/android-sdk/cmdline-tools/cmdline-tools /opt/android-sdk/cmdline-tools/latest \
  && rm /tmp/cmdline-tools.zip \
  && yes | sdkmanager --licenses >/dev/null \
  && sdkmanager "platform-tools" "platforms;android-35" "build-tools;35.0.0" "ndk;30.0.14904198"

WORKDIR /app
COPY package.json ./
COPY server.js ./
COPY asset-protector.js ./
COPY smali-hardening.js ./
COPY THIRD_PARTY_NOTICES.md ./
COPY native-libs ./native-libs
COPY full-vmprotect/release/stable-v20 ./full-vmprotect/release/stable-v20
COPY full-vmprotect/dex_toolchain ./full-vmprotect/dex_toolchain
COPY full-vmprotect/third_party/dcc ./full-vmprotect/third_party/dcc
COPY full-vmprotect/requirements-dcc.txt ./full-vmprotect/requirements-dcc.txt

RUN wget -q "$STABLE_V20_PROTECTED_APK_URL" -O full-vmprotect/release/stable-v20/protected.apk \
  && echo "$STABLE_V20_PROTECTED_APK_SHA256  full-vmprotect/release/stable-v20/protected.apk" | sha256sum -c -

RUN python3 -m pip install --no-cache-dir --break-system-packages -r full-vmprotect/requirements-dcc.txt

RUN mkdir -p tools work out \
  && wget -q https://github.com/iBotPeaches/Apktool/releases/download/v3.0.2/apktool_3.0.2.jar -O tools/apktool_3.0.2.jar

EXPOSE 7860
CMD ["node", "server.js"]
