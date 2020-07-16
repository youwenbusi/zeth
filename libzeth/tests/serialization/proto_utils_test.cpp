// Copyright (c) 2015-2020 Clearmatics Technologies Ltd
//
// SPDX-License-Identifier: LGPL-3.0+

#include "libzeth/circuits/circuit_types.hpp"
#include "libzeth/serialization/proto_utils.hpp"
#include "zeth_config.h"

#include <gtest/gtest.h>

using pp = libzeth::defaults::pp;
using Fr = libff::Fr<pp>;
using G1 = libff::G1<pp>;
using G2 = libff::G2<pp>;

namespace
{

TEST(ProtoUtilsTest, PointG1AffineEncodeDecode)
{
    G1 g1 = Fr(13) * G1::one();
    g1.to_affine_coordinates();
    zeth_proto::HexPointBaseGroup1Affine g1_proto =
        libzeth::point_g1_affine_to_proto<pp>(g1);
    const G1 g1_decoded = libzeth::point_g1_affine_from_proto<pp>(g1_proto);

    ASSERT_EQ(g1, g1_decoded);
}

TEST(ProtoUtilsTest, PointG2AffineEncodeDecode)
{
    G2 g2 = Fr(13) * G2::one();
    g2.to_affine_coordinates();
    zeth_proto::HexPointBaseGroup2Affine g2_proto =
        libzeth::point_g2_affine_to_proto<pp>(g2);
    const G2 g2_decoded = libzeth::point_g2_affine_from_proto<pp>(g2_proto);

    ASSERT_EQ(g2, g2_decoded);
}

// TODO: Add test for joinsplit_input_from_proto

TEST(ProtoUtilsTest, PrimaryInputsEncodeDecode)
{
    const std::vector<Fr> inputs{Fr(1), Fr(21), Fr(321), Fr(4321)};
    std::string inputs_string = libzeth::primary_inputs_to_string<pp>(inputs);
    std::cout << "inputs_string: " << inputs_string << std::endl;
    const std::vector<Fr> inputs_decoded =
        libzeth::primary_inputs_from_string<pp>(inputs_string);
    ASSERT_EQ(inputs, inputs_decoded);
}

TEST(ProtoUtilsTest, AccumulationVectorEncodeDecode)
{
    const libsnark::accumulation_vector<G1> acc_vect(
        G1::random_element(), {G1::random_element(), G1::random_element()});
    const std::string acc_vect_string =
        libzeth::accumulation_vector_to_string<pp>(acc_vect);
    const libsnark::accumulation_vector<G1> acc_vect_decoded =
        libzeth::accumulation_vector_from_string<pp>(acc_vect_string);
    const std::string acc_vect_decoded_string =
        libzeth::accumulation_vector_to_string<pp>(acc_vect_decoded);

    ASSERT_EQ(acc_vect, acc_vect_decoded);
    ASSERT_EQ(acc_vect_string, acc_vect_decoded_string);
}

} // namespace

int main(int argc, char **argv)
{
    pp::init_public_params();
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
