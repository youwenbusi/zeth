// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#ifndef __ZETH_FFI_FFI_UTILS_HPP__
#define __ZETH_FFI_FFI_UTILS_HPP__

#include "libzeth/core/include_libff.hpp"
#include "libzeth/core/utils.hpp"

template<typename objectT>
bool _object_write(const objectT &v, void *out_buffer, size_t size)
{
    std::stringstream ss;
    ss << v;
    const std::string v_bytes = ss.str();

    if (size != v_bytes.size()) {
        printf(
            "_object_write: serialized element was %zu bytes, buffer was %zu\n",
            v_bytes.size(),
            size);
        return false;
    }

    memcpy(out_buffer, &v_bytes[0], size);
    return true;
}

template<typename objectT>
bool _object_read(objectT &v, const void *in_buffer, size_t size)
{
    std::stringstream ss((const char *)in_buffer, size);
    ss >> v;
    return true;
}

template<typename groupT>
bool _group_element_write(const groupT &v, void *out_buffer, size_t size)
{
    std::stringstream ss;
    v.write_uncompressed(ss);
    const std::string v_bytes = ss.str();

    if (size != v_bytes.size()) {
        printf(
            "_group_element_write: serialized element was %zu bytes, expected "
            "%zu\n",
            v_bytes.size(),
            size);
        return false;
    }

    memcpy(out_buffer, &v_bytes[0], size);
    return true;
}

template<typename groupT>
bool _group_element_read(groupT &v, const void *in_buffer, size_t size)
{
    std::stringstream ss((const char *)in_buffer, size);
    groupT::read_uncompressed(ss, v);
    return true;
}

template<typename ppT> bool _Fr_one(void *out_buffer, size_t size)
{
    using FieldT = libff::Fr<ppT>;

    if (size != sizeof(FieldT)) {
        printf("_Fr_one: expected %zu bytes, got %zu\n", sizeof(FieldT), size);
        return false;
    }

    return _object_write<FieldT>(FieldT::one(), out_buffer, size);
}

template<typename ppT>
bool _Fr_sum(
    void *out_buffer,
    size_t out_size,
    const void *fr_A,
    size_t fr_A_size,
    const void *fr_B,
    size_t fr_B_size)
{
    using FieldT = libff::Fr<ppT>;

    FieldT A;
    FieldT B;
    if (!_object_read<FieldT>(A, fr_A, fr_A_size) ||
        !_object_read<FieldT>(B, fr_B, fr_B_size)) {
        return false;
    }

    const FieldT result = A + B;
    if (!_object_write(result, out_buffer, out_size)) {
        return false;
    }

    return true;
}

template<typename ppT> bool _G1_one(void *out_buffer, size_t size)
{
    using G1 = libff::G1<ppT>;
    return _group_element_write<G1>(G1::one(), out_buffer, size);
}

template<typename ppT>
bool _G1_sum(
    void *out_buffer,
    size_t out_size,
    const void *g1_A,
    size_t g1_A_size,
    const void *g1_B,
    size_t g1_B_size)
{
    using G1 = libff::G1<ppT>;

    G1 A;
    G1 B;
    if (!_group_element_read<G1>(A, g1_A, g1_A_size) ||
        !_group_element_read<G1>(B, g1_B, g1_B_size)) {
        return false;
    }

    const G1 result = A + B;
    if (!_group_element_write<G1>(result, out_buffer, out_size)) {
        return false;
    }

    return true;
}

template<typename ppT>
bool _G1_scalar_mul(
    void *out_buffer,
    size_t out_size,
    const void *g1_element,
    size_t g1_element_size,
    const void *fr_element,
    size_t fr_element_size)
{
    using Field = libff::Fr<ppT>;
    using G1 = libff::G1<ppT>;

    G1 g;
    Field f;
    if (!_group_element_read(g, g1_element, g1_element_size) ||
        !_object_read(f, fr_element, fr_element_size)) {
        return false;
    }

    const G1 result = f * g;
    if (!_group_element_write(result, out_buffer, out_size)) {
        return false;
    }

    return true;
}

template<typename ppT> bool _G2_one(void *out_buffer, size_t size)
{
    using G2 = libff::G2<ppT>;
    return _group_element_write<G2>(G2::one(), out_buffer, size);
}

#endif // __ZETH_FFI_FFI_UTILS_HPP__
