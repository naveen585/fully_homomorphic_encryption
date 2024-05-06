load("@bazel_skylib//:bzl_library.bzl", "bzl_library")
load("//transpiler:fhe.bzl", "fhe_cc_library")
load("//transpiler/rust:fhe_rs.bzl", "fhe_rust_library")
load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")

licenses(["notice"])

cc_library(
    name = "max_number",
    srcs = ["max_number.cc"],
    hdrs = ["max_number.h"],
)

fhe_cc_library(
    name = "max_number_tfhe",
    src = "max_number.cc",
    hdrs = ["max_number.h"],
    encryption = "tfhe",
    num_opt_passes = 2,
    optimizer = "xls",
)

cc_binary(
    name = "max_number_tfhe_testbench",
    srcs = ["max_number_tfhe_testbench.cc"],
    deps = [
        ":max_number_tfhe",
        "//transpiler/data:tfhe_data",
        "@com_google_xls//xls/common/logging",
        "@com_google_xls//xls/common/status:status_macros",
        "@tfhe//:libtfhe",
    ],
)