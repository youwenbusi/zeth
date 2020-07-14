// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "ffi_utils.hpp"

#include <libff/algebra/curves/bls12_377/bls12_377_pp.hpp>
#include <libff/algebra/curves/bw6_761/bw6_761_pp.hpp>

extern "C" bool initialize();

extern "C" bool bls12_377_Fr_one(void *out_buffer, size_t size);
extern "C" bool bls12_377_Fr_sum(
    void *out_buffer,
    size_t size,
    const void *fr_A,
    size_t fr_A_size,
    const void *fr_B,
    size_t fr_B_size);

extern "C" bool bls12_377_G1_one(void *out_buffer, size_t size);
extern "C" bool bls12_377_G1_sum(
    void *out_buffer,
    size_t size,
    const void *g1_A,
    size_t g1_A_size,
    const void *g1_B,
    size_t g1_B_size);
extern "C" bool bls12_377_G1_scalar_mul(
    void *out_buffer,
    size_t out_size,
    const void *g1_element,
    size_t g1_element_size,
    const void *fp_element,
    size_t fp_element_size);

extern "C" bool bls12_377_G2_one(void *out_buffer, size_t size);

// template<typename ppT, typename groupT>
// bool _group_element_multi_scalar_mul(
//     void *out_buffer,
//     size_t out_size,
//     size_t num_elements,
//     const void *const *group_elements,
//     size_t group_element_size,
//     const void *const *scalars,
//     size_t scalar_size)
// {
//     using FieldT = libff::Fr<ppT>;

//     groupT acc = groupT::zero();
//     for (size_t i = 0; i < num_elements; ++i) {
//         printf("i=%zu: %p, %p\n", i, group_elements[i], scalars[i]);
//     }

//     return false;
// }

bool initialize()
{
    libff::bls12_377_pp::init_public_params();
    libff::bw6_761_pp::init_public_params();
    return true;
}

bool bls12_377_Fr_one(void *out_buffer, size_t size)
{
    return _Fr_one<libff::bls12_377_pp>(out_buffer, size);
}

bool bls12_377_Fr_sum(
    void *out_buffer,
    size_t out_size,
    const void *fr_A,
    size_t fr_A_size,
    const void *fr_B,
    size_t fr_B_size)
{
    return _Fr_sum<libff::bls12_377_pp>(
        out_buffer, out_size, fr_A, fr_A_size, fr_B, fr_B_size);
}

bool bls12_377_G1_one(void *out_buffer, size_t size)
{
    return _G1_one<libff::bls12_377_pp>(out_buffer, size);
}

bool bls12_377_G1_sum(
    void *out_buffer,
    size_t out_size,
    const void *g1_A,
    size_t g1_A_size,
    const void *g1_B,
    size_t g1_B_size)
{
    return _G1_sum<libff::bls12_377_pp>(
        out_buffer, out_size, g1_A, g1_A_size, g1_B, g1_B_size);
}

bool bls12_377_G1_scalar_mul(
    void *out_buffer,
    size_t size,
    const void *g1_element,
    size_t g1_element_size,
    const void *fp_element,
    size_t fp_element_size)
{
    return _G1_scalar_mul<libff::bls12_377_pp>(
        out_buffer,
        size,
        g1_element,
        g1_element_size,
        fp_element,
        fp_element_size);
}

bool bls12_377_G2_one(void *out_buffer, size_t size)
{
    return _G2_one<libff::bls12_377_pp>(out_buffer, size);
}
