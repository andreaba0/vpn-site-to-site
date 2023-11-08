cc_library(
    name="ip_packet",
    srcs=["ip_packet.cc"],
    hdrs=["ip_packet.h"],
)

cc_library(
    name="network_interface",
    srcs=["network_interface.cc"],
    hdrs=["network_interface.h"],
)

cc_binary(
    name="main",
    srcs=["main.cc"],
    deps=[
        ":ip_packet",
        ":network_interface",
    ],
)