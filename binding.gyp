{
  "targets": [
    {
      "target_name": "gift-cofb",
      "sources": [
        "src/addon.cpp",
        "src/cipher.cpp",
        "src/gift_cofb.c",
        "src/gift128.c",
        "src/wrapper.cpp",
        "src/crypto_utils.c"
      ],
      "include_dirs": ["<!(node -e \"require('nan')\")"],
    }
  ]
}
