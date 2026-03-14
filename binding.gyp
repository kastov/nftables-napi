{
  "targets": [
    {
      "target_name": "nftables_napi",
      "sources": [
        "src/addon.cpp",
        "src/nft_manager.cpp",
        "src/validation.cpp",
        "src/netlink/nl_batch.cpp",
        "src/netlink/nl_socket.cpp",
        "src/netlink/set_ops.cpp",
        "src/netlink/table_ops.cpp",
        "src/workers/nft_worker.cpp"
      ],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")",
        "<!@(pkg-config --cflags-only-I libnftnl libmnl | sed 's/-I//g')"
      ],
      "libraries": [
        "<!@(pkg-config --libs libnftnl libmnl)"
      ],
      "defines": [
        "NAPI_VERSION=9",
        "NAPI_DISABLE_CPP_EXCEPTIONS"
      ],
      "cflags_cc": [
        "-std=c++20",
        "-Wall",
        "-Wextra",
        "-Wpedantic",
        "-Wno-unused-parameter",
        "-D_FORTIFY_SOURCE=2",
        "-fstack-protector-strong"
      ],
      "ldflags": [
        "-Wl,-z,relro",
        "-Wl,-z,now",
        "-Wl,-z,noexecstack"
      ],
      "conditions": [
        ["OS!='linux'", {
          "defines": ["UNSUPPORTED_PLATFORM"]
        }]
      ]
    }
  ]
}
