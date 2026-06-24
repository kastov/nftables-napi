FROM node:24-alpine AS builder

# musl build -> links against libnftnl.so.11
RUN apk add --no-cache python3 make g++ pkgconf libnftnl-dev libmnl-dev linux-headers

WORKDIR /pkg

COPY package.json binding.gyp ./
COPY src/ src/

RUN npm install --ignore-scripts
# --tag-libc names the output nftables-napi.musl.node so node-gyp-build can
# pick the right binary for the host libc at runtime.
RUN npx prebuildify --napi --strip --tag-libc=musl

# Prebuilds are now in /pkg/prebuilds/

FROM scratch
COPY --from=builder /pkg/prebuilds /prebuilds
