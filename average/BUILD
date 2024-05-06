load("@bazel_skylib//:bzl_library.bzl", "bzl_library")
load("//transpiler:fhe.bzl", "fhe_cc_library")
load("//transpiler/rust:fhe_rs.bzl", "fhe_rust_library")
load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

licenses(["notice"])

cc_library(
    name = "average",
    srcs = ["average.cc"],
    hdrs = ["average.h"],
)

fhe_cc_library(
    name = "average_tfhe",
    src = "average.cc",
    hdrs = ["average.h"],
    encryption = "tfhe",
    num_opt_passes = 2,
    optimizer = "xls",
)

cc_binary(
    name = "average_tfhe_testbench",
    srcs = ["average_tfhe_testbench.cc"],
    deps = [
        ":average_tfhe",
        "//transpiler/data:tfhe_data",
        "@com_google_xls//xls/common/logging",
        "@com_google_xls//xls/common/status:status_macros",
        "@tfhe//:libtfhe",
    ],
)