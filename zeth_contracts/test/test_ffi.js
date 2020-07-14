// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+


var ffi = require('@saleae/ffi');

var libff_functions = {
    "initialize": ["bool", []],
    "bls12_377_Fr_one": ["bool", ["void *", "size_t"]],
    "bls12_377_Fr_sum": [
        "bool",
        ["void *", "size_t", "void *", "size_t", "void *", "size_t"]
    ],

    "bls12_377_G1_one": ["bool", ["void *", "size_t"]],
    "bls12_377_G1_sum": [
        "bool",
        ["void *", "size_t", "void *", "size_t", "void *", "size_t"]
    ],
    "bls12_377_G1_scalar_mul": [
        "bool",
        ["void *", "size_t", "void *", "size_t", "void *", "size_t"]
    ],

    "bls12_377_G2_one": ["bool", ["void *", "size_t"]],
};

try {
    var libff = ffi.Library("libff-ffi", libff_functions);
} catch(e) {
    console.log("Error loading dynamic library: " + e);
    console.log("  (set LD_LIBRARY_PATH or DYLD_LIBRARY_PATH)");
    process.exit(1);
}

const BLS12_377_FR_SIZE_BYTES = 32;
const BLS12_377_G1_SIZE_BYTES = 97;
const BLS12_377_G2_SIZE_BYTES = 193;

function bls12_377_Fr_one()
{
    var b = Buffer.alloc(BLS12_377_FR_SIZE_BYTES);
    if (!libff.bls12_377_Fr_one(b, b.length)) {
        return null;
    }
    return b;
}

function bls12_377_Fr_sum(a, b)
{
    var b = Buffer.alloc(BLS12_377_FR_SIZE_BYTES);
    if (!libff.bls12_377_Fr_sum(b, b.length, a, a.length, b, b.length)) {
        return null;
    }
    return b;
}

function bls12_377_G1_one()
{
    var b = Buffer.alloc(BLS12_377_G1_SIZE_BYTES);
    if (!libff.bls12_377_G1_one(b, b.length)) {
        return null;
    }
    return b;
}

function bls12_377_G1_sum(a, b)
{
    var b = Buffer.alloc(BLS12_377_G1_SIZE_BYTES);
    if (!libff.bls12_377_G1_sum(b, b.length, a, a.length, b, b.length)) {
        return null;
    }
    return b;
}

function bls12_377_G1_scalar_mul(g, scalar)
{
    var b = Buffer.alloc(BLS12_377_G1_SIZE_BYTES);
    if (!libff.bls12_377_G1_scalar_mul(
        b, b.length, g, g.length, scalar, scalar.length)) {
        return null;
    }
    return b;
}

function bls12_377_G2_one()
{
    var b = Buffer.alloc(BLS12_377_G2_SIZE_BYTES);
    if (!libff.bls12_377_G2_one(b, b.length)) {
        return null;
    }
    return b;
}

function bls12_377_G1_multi_scalar_mul(g1_elements, scalars)
{
    throw "unimplemented";
}

function bls12_377_eee_equals_e(P1, Q1, P2, Q2, P3, Q3, P4, Q4)
{
    throw "unimplemented";
}

function test()
{
    var r;
    r = libff.initialize();
    console.log("init: r=" + r);

    var fr_one = bls12_377_Fr_one()
    console.log("bls12_377_Fr_one=" + fr_one.hexSlice());

    var g1_one = bls12_377_G1_one();
    console.log("bls12_377_G1_one=" + g1_one.hexSlice());

    var g2_one = bls12_377_G2_one();
    console.log("bls12_377_G2_one=" + g2_one.hexSlice());

    // Simple addition / scalar mul test
    var g1_2_from_sum = bls12_377_G1_sum(g1_one, g1_one);
    console.log("g1_2_from_sum = " + g1_2_from_sum.hexSlice());

    var fr_2 = bls12_377_Fr_sum(fr_one, fr_one);
    var g1_2_from_scalar_mul = bls12_377_G1_scalar_mul(g1_one, fr_2);
    console.log("g1_2_from_scalar_mul = " + g1_2_from_scalar_mul.hexSlice());

    if (0 !== Buffer.compare(g1_2_from_sum, g1_2_from_scalar_mul)) {
        throw "g1_2 inconsistency";
    }
}

test();
